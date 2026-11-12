# 2026-11-12 — Research status: Qualcomm Fastboot CVE-2026-24091 / 24092 vs original HONOR 70 ABL

**Device:** HONOR 70 FNE-NX9, European C431, MagicOS 8.0.0.290.  
**Source authenticity:** Original signed retail `LinuxLoader.efi`, SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`, 3,309,568 bytes.

**Important:** **No reproduced privilege escalation, arbitrary code execution, unlocked bootloader or working exploit** on this model has been demonstrated. Everything below is **offline original-firmware analysis**. No malformed Fastboot commands were sent to the phone and no partition was written.

## Public vulnerabilities and scope

Qualcomm's [June 2026 Security Bulletin](https://docs.qualcomm.com/product/publicresources/securitybulletin/june-2026-bulletin.html) lists:

- [CVE-2026-24091](https://nvd.nist.gov/vuln/detail/CVE-2026-24091): memory corruption while parsing malformed Fastboot commands (CVSS 7.2).
- [CVE-2026-24092](https://nvd.nist.gov/vuln/detail/CVE-2026-24092): memory corruption while processing display-mode Fastboot commands (CVSS 7.2).

These descriptions do **not** give a function offset, a suitable proof-of-concept, a known supported/unpatched FNE-NX9 build, or a persistent bootloader-unlock demonstration. Some public CVE databases report broad platform names from CPE guesses. Qualcomm's published affected-version metadata is largely redacted; **do not claim our HONOR build is necessarily vulnerable merely because it uses Snapdragon 778G Plus**.

## Original EEA ABL command surface checked

- [Successful original exact-string and code-reference audit #43128174561](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43128174561)
- [Code: original signed Fastboot command surface scanner](../tools/audit_abl_2026_fastboot_exploit_surface.py)

Observed:
- `set-gpu-preemption`, `set-hw-fence-value`, `gpu-preemption`: **no exact ASCII/UTF-16LE matches in original LinuxLoader**.
- `efisp`, `gbl.efi`, `generic bootloader`: **no exact ASCII/UTF-16LE matches in original LinuxLoader**; earlier signed GPT inventory also has no `efisp`. Thus the public GPU-preemption → unsigned GBL chain has **no proven prerequisites** here.
- Actual signed firmware includes `flash:slockv1`, `fastboot flash:rdmodev1`, `oem unlock`, `flashing unlock`, `oem select-display-panel` and more. String presence alone does not demonstrate privilege bypass.

## Signed service mode handlers: real, but no signature bypass found

- [Ghidra 8.0.0.290 original SLock and RD-mode handlers #43128395793](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43128395793)
- [Full signed code review #43128640083](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43128640083)
- [Post-verification handlers #43128891014](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43128891014)
- [Original post-verification helper expansion #43129261324](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43129261324)

**`flash:slockv1`** has original EEA handler `FUN_00016DD4`, which calls `FUN_0001BB68(...,0,1)` for a signed request. Invalid signature branch emits `sign data not match`. Its successfully verified path updates a separate software state and builds a response; it does not directly call Keymaster `0x203`.

**`flash:rdmodev1`** has handler `FUN_000172A4`, using `FUN_0001BB68(...,2,2)` with the signed `fastboot flash:rdmodev1` descriptor; a successful signed request can invoke `FUN_0001381C(0x82,...,0x100)`, an **OEMINFO record 130 write**, not an observed persistent Keymaster lock write. `FUN_0001BB68` has code/logging associated with SHA-256/RSA-PSS signature verification. Its decompiler may misrecover prototypes, so the exact signature-validation implementation remains to be fully proved. **No working signature bypass has been found.**

`FUN_00015B08`, sometimes adjacent in decompiled SLock code, is a **Fastboot response formatter**, not a demonstrated secure state writer.

## CVE-2026-24092: actual display handlers exist but are blocked in locked Fastboot

- [Exact original display-command registration table #43129202726](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43129202726)
- [Original handler Ghidra code #43129403421](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43129403421)
- [Actual parser and locked gate decompilation #43129848151](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43129848151)
- **[Independent crosscheck original display table vs locked 49-prefix allowlist #43129979350](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43129979350) — SUCCESS**.

The original Fastboot command table contains:

| Registered command | Handler RVA | Appears in 49-prefix locked-mode allowlist? |
|---|---:|---|
| `oem select-display-panel` | `0x25E2C` | **No** |
| `oem set-dg-img` | `0x49098` | **No** |
| `oem set-dg-img-resume` | `0x492D0` | **No** |

The original dispatcher `FUN_00022C7C` calls `FUN_000134C0(command)` **before walking the registered handler table**. If the local ABL access context `+0x104` is not `1`, this function checks 49 exact prefix strings; those three display commands match **none**, returning Fastboot `Command not allowed`. Therefore a *direct* attempt to reach a display handler through normal locked Fastboot dispatch is blocked before calling it. That conclusion is grounded in verified source, **not** proof that the CVE is patched on this hardware or that every upstream parser is safe.

The display handler `0x25E2C` itself uses 256-byte temporary buffers and reads/writes UEFI `DisplayPanelOverride`; we have not identified a source-proven memory-safety fault or arbitrary code execution from this handler.

## Higher-priority, still UNPROVEN: common Fastboot pre-gate terminator

A [new signed ABL Fastboot parser review #43130106309](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43130106309) and [full function source trace #43130298528](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43130298528) reveal:

```c
// Simplified control flow from ABL FUN_00022C7C
length = incoming_command_length;
if (length > 0x3f) {
    length = 0x40;
}
incoming_command_buffer[length] = 0;
...
if (FUN_000134C0(incoming_command_buffer) == 1) {
    dispatch_to_registered_handler(...);
} else {
    FAIL("Command not allowed");
}
```

The `[length]` NUL write happens **before** the locked-mode allowlist gate. If the actual command backing allocation is exactly 64 bytes and the parser receives 64 bytes, a 1-byte out-of-bounds write is theoretically possible. **We have not established the backing allocation size, whether the USB transport always allocates spare terminator space, or whether an overwrite could affect control data.** Calling this a confirmed vulnerability, much less a working bootloader-unlock exploit, would be premature.

The parser is entered via the receive callback `FUN_00022A64` and an asynchronous completion callback `FUN_00024364`, which forwards a length/pointer pair from a buffer descriptor. Establishing the **actual allocation and lifetime of this pointer** is a necessary prerequisite to any exploitation assessment.

This source condition should not be equated automatically with CVE-2026-24091: the published CVE has no public vulnerable function offset matching our binary.

## Research decision

**CVE-24092 display handler:** directly blocked by locked-mode allowlist; do not try malformed display commands on the live handset.

**SLock/RDMode:** signed-token verification present; no demonstrated forgery or effect on protected `0x203` state writer; do not write OEMINFO #130, FRP, or SLock state to force access.

**Common pre-gate parser:** review original USB buffer lifetime and allocation; do not send deliberate malformed Fastboot inputs based on an unverified 1-byte write hypothesis. Even a proved crash is not the same as reliable controlled execution and a persistent bootloader unlock.

No working permanent unlock method for HONOR 70 FNE-NX9 C431 MagicOS 8.0.0.290 has been obtained as of this report.
