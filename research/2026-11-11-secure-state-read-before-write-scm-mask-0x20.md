# 2026-11-11 — VerifiedBootDxe secure-state WRITE requires READ; SCM mask delta is bit 0x20

## Reproducible evidence

- [Successful read-only GitHub Actions analysis, run 43114969428](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43114969428).
- Analysis code: [`tools/audit_secure_state_write_prerequisite.py`](../tools/audit_secure_state_write_prerequisite.py).
- Workflow: [`audit-secure-state-prerequisite-20261111.yml`](../.github/workflows/audit-secure-state-prerequisite-20261111.yml).
- Input: existing Ghidra report `VERIFIEDBOOT_DXE_GHIDRA.txt` from successful original signed FNE-NX9 EEA XBL decomposition, run `42538078141`. The Ghidra report originates from the previously verified `VerifiedBootDxe` PE image (SHA256 `f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`). The analysis consumes this report read-only, not a new phone dump.

## Critical ordering: the Keymaster write command is conditional on a prior read

Original EEA `VerifiedBootDxe` `FUN_0000153c` dispatches `param_2==0` to READ and `param_2==1` to WRITE. In the **secure storage WRITE branch**:

1. Allocate the QSEE transport buffer.
2. Set command `0x202` (`READ_KM_DEVICE_STATE`) and submit it.
3. Check **both** the transport result `lVar3==0` and response status `local_d8==0`.
4. **Only on success** copy the requested state and submit `0x203` (`WRITE_KM_DEVICE_STATE`).
5. If the pre-read fails, recheck SCM state via `FUN_00003898`; where secure fallback is forbidden, return an error without calling `0x203`. Other SCM classifications may permit direct `devinfo` writes, not a secure Keymaster write.

The exact decompiled conditional after the `0x202` request is:

```c
if ((lVar3 == 0) && (local_d8 == 0)) {
    FUN_00004b68(puVar6, 0x1000, param_3, (ulonglong)param_4);
    // Build request with 0x203; submit it through QSEE.
} else {
    lVar3 = FUN_00003898(local_ac);
    // If still secure, reject; otherwise direct devinfo fallback may run.
}
```

**Consequence for the prior unsuccessful unlock:** it is **not valid** to conclude that command `0x203` failed or was even invoked simply because unlock did not persist. A failing pre-read `0x202`, missing user confirmation, permission checks or other paths may prevent that call. Previous boot log `-15` observations have not been temporally tied to the Fastboot UI confirmation callback.

## Two different SCM masks and their precise relationship

- First secure-storage selector `FUN_00003904`: `(SCM_security_state & 0x8703) == 0` selects Keymaster/RPMB.
- Failure fallback selector `FUN_00003898`: `(SCM_security_state & 0x8723) == 0` identifies a secure device for which raw fallback is **not** taken.
- `0x8703 XOR 0x8723 = 0x0020` — exactly **one bit** differs.

This creates three logical categories, enumerated by the reproducible script across 65,536 possible **16-bit theoretical state values**:

| Primary path | Failed Keymaster read fallback | 16-bit states |
|---|---|---:|
| Keymaster/RPMB | Raw fallback denied | 512 |
| Keymaster/RPMB | Raw fallback condition met | 512 |
| Raw `devinfo` | Secure pre-read not used | 64,512 |

Examples:
- `0x0000` -> Keymaster initially, no raw fallback after a failed read.
- `0x0020` -> Keymaster initially, fallback check classifies it as eligible for direct devinfo after failure.
- `0x0001` or `0x0021` -> direct devinfo initially.

These are **mathematical classes**, **not** measurements of the user's phone; class counts do not represent frequencies or probabilities. The `0x0020` example demonstrates a static conditional disagreement in the two functions, **not** an experimentally verified unlock bypass. We do not know whether the phone's Qualcomm SCM interface can report this combination or what other secure state effects it implies.

## Limits and safe next direction

- No EDL, Fastboot, Qualcomm SCM, Keymaster, RPMB, UFS, OEMINFO or other **live** operation was performed.
- Static Ghidra pseudocode may have incorrect prototypes or error variable aliases. The tool asserts observed gates but is not a formal whole-program proof.
- No evidence yet identifies the exact security state/fuse value on the user's device, nor confirms an attempted `0x203` from their previous UI-based unlock.
- Do not try to force or change SCM bit `0x20`, patch signed trustlets, or write `devinfo` to exercise this conditional. A different theoretical selector branch is not a demonstrated safe bootloader-unlock procedure.

**Next diagnostic target:** correctly attribute a genuine *historical* Fastboot confirmation event to the ABL `VBRwDevice READ` result before the write. If historic logs do not contain such a trace, offline firmware analysis alone cannot establish which live step failed. New invasive attempts should not be based on the mask table.
