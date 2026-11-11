# 2026-11-11 — ABL UI callback ↔ Keymaster READ guard: original ARM64 and fuse error provenance

**Device/build:** HONOR 70 FNE-NX9 EEA, FNE-N29 MagicOS 8.0.0.290 C431.  
**Method:** Offline analysis of exact original EEA `LinuxLoader.efi` plus previously generated Keymaster Ghidra decompilation.  
**Status:** No confirmed permanent bootloader unlock; no new phone operation or flash.

## Reproduction and provenance

- [Successful callback + Keymaster gate audit](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43116062047) — verified original ABL instructions and the Keymaster gate function inventory.
- [Successful follow-up with source-local fuse and -15 excerpts](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43116216616).
- [Reproducible Python parser/disassembler](../tools/audit_abl_callback_keymaster_read.py).
- [GitHub Actions workflow](../.github/workflows/audit-abl-callback-km-read-20261111.yml).
- **Original ABL LinuxLoader SHA-256:** `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`.
- Previously decompiled original EEA Keymaster Ghidra report: [run 42540518094](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42540518094).

The script checks actual ABL ARM64 call and branch addresses, extracts functions from the existing Keymaster Ghidra report, captures relevant pseudocode excerpts, and publishes metadata. It makes **no EDL, Fastboot, QSEE or RPMB request**.

## Step 1 — Asynchronous UI confirmation makes its own VBRwDevice READ

Verified original ABL instructions:

```asm
0x3d9e0  bl   #0x37ac0       ; VBRwDevice wrapper, w0=0 (READ)
0x3d9e4  cbz  x0, #0x3da48   ; read succeeded (zero EFI status)
  ...                        ; error-path/UI handling otherwise
0x3da48  adrp x8, ...
0x3da50  add  x8, x8, x21, lsl #4
0x3da54  ldr  w0, [x8]      ; desired state argument
0x3da58  ldrb w1, [x8, #8]
0x3da5c  bl   #0x43688      ; request state transition
0x3da60  cbz  x0, #0x3da98  ; returned success/error controls next UI path
```

**Consequence:** the callback cannot normally call the state setter through this route until the preceding READ succeeds. A UI confirmation (or initial Fastboot `OKAY`) by itself is not evidence of a successful read or write.

## Step 2 — ABL state setter issues a second protocol request

Inside `0x43688`, the ABL setter chooses the relevant state field and calls `0x37ac0` with operation 1:

```asm
0x4370c mov  w0, #1
0x43710 strb w23, [x1, #0xd]   ; in-memory request buffer
0x43714 bl   #0x37ac0
...
0x43764 mov  w0, #1
0x43768 strb w23, [x1, #0xe]   ; alternate in-memory request field
0x4376c bl   #0x37ac0
```

`0x37ac0` is a UEFI protocol wrapper; it forwards an operation and a state buffer to the `VBRwDevice` interface. Offsets `+0xd` and `+0xe` in this section are **not** established UFS `devinfo` offsets.

## Step 3 — VBRwDevice WRITE itself requires a Keymaster pre-read

Original EEA `VerifiedBootDxe` `0x153c` [previously verified](2026-11-11-secure-state-read-before-write-scm-mask-0x20.md):

When the live SCM state chooses secure Keymaster/RPMB:
1. The UI's VBRwDevice **READ** issues Keymaster `0x202`.
2. After a successful UI callback READ, the ABL state setter issues a separate VBRwDevice **WRITE** request.
3. That VBRwDevice WRITE issues **another Keymaster `0x202`** to obtain the existing state.
4. Only if *that* read's transport and returned status succeed does it issue Keymaster `0x203`.

Thus a successfully progressing, **secure-backed** UI unlock path normally contains **two separate `0x202` requests before `0x203`**. A failure anywhere earlier can prevent `0x203` from ever being called. This is a conditional path reconstruction, not a live request count measured on the user's phone.

## Step 4 — Why Keymaster -15 does NOT prove the milestone fuse is blown

The exact original EEA Keymaster functions were identified:

| Handler | RVA | Static observations |
|---|---|---|
| READ `0x202` | `0x1185a8` | calls `FUN_00117980`; contains `0xfffffff1` |
| WRITE `0x203` | `0x118878` | calls `FUN_00117980`; contains `0xfffffff1` |
| Fuse-check helper | `0x117980` | calls `qsee_is_sw_fuse_blown(1, ...)` |
| Milestone setter | `0x117a18` | contains `qsee_blow_sw_fuse` (do NOT invoke) |

Both READ and WRITE check a return code `iVar1` and fuse-result byte `local_4c[0]` (or `acStack_4c[0]`) before entering RPMB work:

```c
iVar1 = FUN_00117980(local_4c);
if ((iVar1 == 0) && (local_4c[0] == '\0')) {
    // Proceed to Keymaster protected-storage work
} else {
    // Log indicates check failed OR fuse already blown
    uVar5 = 0xfffffff1; // -15 as signed 32-bit
}
```

The helper calls `qsee_is_sw_fuse_blown(1, local_2c, 1)` and, on a successful primitive call, transfers the result to the caller. On an unsuccessful primitive call, it produces an error. **Therefore the single READ/WRITE error code `-15` conflates a failed fuse-check operation with a returned blown state.** It is not sufficient to infer the live fuse value.

Other storage-stage functions, including `qsee_stor_read_sectors` and `qsee_stor_write_sectors`, can fail separately. Error attribution requires the actual source branch and its associated log, not merely a numeric code detached from boot context.

## What can and cannot be concluded for this exact phone

**Proven in EEA code:** the UI read-first gate, the state setter's VBRwDevice write operation, the secure writer's pre-read-before-`0x203` gate, and the dual-cause `-15` fuse-check rejection.

**Not proven on the live handset:** that the previous UI attempt reached either of the two secure reads; that it reached `0x203`; whether its SCM security mask selects the Keymaster path; whether the fuse is physically blown; why the lock failed to persist.

The prior [EDL UEFI log interpretation](2026-11-09-original-fastboot-ui-rpmb-gate-correction.md) found `read status -15` in Linux-boot records, **not** the Fastboot-only slot. Do not retroactively assign that `-15` to the UI callback.

## Research gate

Until a genuine **existing historical** callback trace can distinguish the two READs and the write result, speculative changes to `devinfo`, OEMINFO, RPMB, SCM bits, Keymaster, ABL, XBL, or GPT are not justified. No repeat of a data-wiping unlock attempt is requested. The next offline step is comparing the callback's exact error-to-UI messaging and the two secure request failure paths in the **same build**, or searching previous already-collected UEFI traces without uploading raw private device data.
