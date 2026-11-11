# 2026-11-12 — VerifiedBoot reset slot is Keymaster DELETE_ALL_KEYS (0x10E), not device unlock WRITE (0x203)

## Independently verified, source-pinned result

**[Cross-firmware GitHub Actions verification, run 43121032094](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43121032094)** completed successfully. This job joined **two previously independently produced artifacts** from the user's original signed European MagicOS 8.0.0.290 firmware:

1. [Original XBL PE vtable and ARM64 target analysis, run 43120424282](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43120424282), exact `VerifiedBootDxe.efi` SHA256 `f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`.
2. [Original `km41.mbn` Ghidra command-dispatch labels, run 42539726689](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42539726689), the original EEA signed Keymaster `km41.mbn` SHA256 was pinned in its original extraction workflow as `c7f389b80444a9c9e3956efd427abbae1b5b2753b3c905107ca7888dca496afd`.

The second report's SHA256 is `a014a4cca5a442f00eee55bad38ed04987338cc7badd214962fc4a43b9f97bcc`.

**Reproducible code:** [`tools/audit_km_reset_delete_all_keys.py`](../tools/audit_km_reset_delete_all_keys.py) and [workflow](../.github/workflows/audit-km-reset-delete-all-keys-20261112.yml). Both use archived, signed source evidence; **no device command was sent**.

## Exact verified protocol linkage

The original XBL PE has an initialized array at **RVA/file offset `0xD160`** with protocol revision-like value `0x10003`.

The code at `0x27E8` references the VerifiedBoot GUID (`8e5eff91-21b6-47d3-af2b-c15a01e020ec`, RVA `0xD0A8`); `0x27EC` references the initialized array (`0xD160`). Both are arguments at the same nearby UEFI Boot Services indirect registration call (`0x2804`). This establishes **far stronger evidence than string or table proximity alone** that the array is the live provider's protocol table.

- ABL `0x37AC0` forwards normal `VBRwDevice` access to provider method offset `+0x08`, target XBL RVA **`0x153C`**.
- ABL `0x38370` invokes provider method offset `+0x30`, target XBL RVA **`0x1C84`**.
- These are **two different provider methods**.

## What the verified XBL handler at RVA 0x1C84 does

Instruction-level evidence from the SHA-pinned original PE:

```asm
0x1d68  mov  w8, #0x10e
0x1d6c  add  x2, x29, #0x18
0x1d74  mov  w3, #4
0x1d78  mov  w5, #4
0x1d7c  str  w8, [x29, #0x18]
0x1d80  ldr  x9, [x0, #0x18]
0x1d84  blr  x9
0x1d88  ldr  w3, [sp]
0x1d90  cbnz x0, #0x1da0
0x1d94  cbnz w3, #0x1da0
```

The method has a QSEE/Keymaster app initialization and a **distinct four-byte request whose command field is 0x10E**, sent via an indirect QSEE protocol method. It checks both the transport return and the response word for zero before treating the operation as successful. Error paths exist for loading the app, sending the command and receiving the status; presence of this code does not prove successful execution on the owner's handset.

## Independent Keymaster meaning of 0x10E

The **original signed European Keymaster** Ghidra function `FUN_0010D7C8` contains the explicit command-name selection:

```c
case 0x10d: pcVar2 = "DELETE_KEY"; break;
case 0x10e: pcVar2 = "DELETE_ALL_KEYS"; break;
case 0x10f: pcVar2 = "BEGIN"; break;
...
case 0x202: pcVar2 = "READ_KM_DEVICE_STATE"; break;
case 0x203: pcVar2 = "WRITE_KM_DEVICE_STATE"; break;
case 0x204: pcVar2 = "MILESTONE_CALL"; break;
```

Therefore the **VerifiedBoot provider's method +0x30 is a Keymaster DELETE_ALL_KEYS requester**, not the protected unlock-state writer. This matches the fact that ABL can invoke it before a recovery `--wipe_data` sequence.

**Important limitation:** the command's original label is verified. We have not dynamically executed the request or reconstructed every internal storage side effect of the corresponding trustlet handler, so do not claim which exact cryptographic keys or RPMB records it erases.

## Implication for the original failed unlock attempt

The now-proven stock ABL `0x43688` has two ways to reach the shared reset/wipe path:

1. **Equal-state path:** the ABL-local getter `0x13008` says the desired logical state is already present, so the setter **does not send another** `VBRwDevice WRITE` call.
2. **Write-success path:** the ABL does call `VBRwDevice WRITE` and receives a zero status.

Both converge to `0x437A0` and can call the separate `+0x30` provider operation `0x1C84`, which sends `DELETE_ALL_KEYS (0x10E)`. After successful checks, the firmware can stage a recovery wipe command.

Thus a cryptographic reset and wipe may coexist with **no new Keymaster `WRITE_KM_DEVICE_STATE (0x203)` request** on the equality path. This is **exact stock firmware behavior**, not an observation that this path actually occurred in the owner's previous unlock attempt.

It is no longer appropriate to call provider `+0x30` an unlock-state reset or to infer that a successful wipe means the Keymaster's 0x203 operation was attempted.

## What remains unresolved

- Did the *live* ABL-local state `+0x104`, which is at least partly initialized from OEMINFO `0x82` (decimal 130), compare equal to the requested unlock state? No device observation proves that.
- Which UEFI callback and security backend did the previous unlock confirmation actually take? No historical Fastboot-only trace pins it down.
- If a secure state WRITE was attempted, did its Keymaster pre-read `0x202` succeed? The fuse bit and SCM security-state value are unknown.
- Did the device's persistent lock state ever change? Its subsequent visible outcome remained LOCKED.

**The next meaningful investigation is the state comparison and the persistent backend selection**, not a repeated OEMINFO, FRP, devinfo, or Keymaster replacement write. No EDL operation can be justified merely by the newly identified delete-all-keys path.
