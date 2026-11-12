# 2026-11-12 — Four remaining GhostLock C431 tasks: independently audited status

**Target:** own HONOR 70 **FNE-NX9**, region **C431**, MagicOS **8.0.0.290**, exact kernel `5.4.295-qgki-ga2d8945339ca`.

This report responds to a request to complete the four prerequisites for an attempted C431 GhostLock temporary-root port. It distinguishes actual proof from static candidates. **No functioning GhostLock root on this exact handset has been achieved.**

## Evidence gate: completed and reproducible

[**GitHub Actions run 43291260101 — SUCCESS**](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43291260101): 12/12 fail-closed tests passed; the checker then consumed **five earlier original-retail, SHA-pinned artifacts**:

| Evidence | Previously independently checked CI |
|---|---|
| Original `futex_requeue → rt_mutex_start_proxy_lock → remove_waiter` static source+binary chain | [43274625423](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43274625423) |
| Original `futex_requeue` direct `bl` to proxy wrapper | [43275022781](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43275022781) |
| Original C431 waiter/select stack interval arithmetic | [43283106736](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43283106736) |
| Original inlined waiter pointer provenance | [43282279278](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43282279278) |
| Original embedded IKCONFIG hardening | [43287116480](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43287116480) |

The checker refuses mismatched original `boot.img` SHA256 `5f27556ef26cf84f8ad6ff304a966c4b246091c01c89d8fd8f33e5526f7f3256`, original kernel `Image` SHA256 `bd8622b9448e435fb1459cefab59458988fc85c02a829cb5f47f9b03cc2c2ece`, and original embedded IKCONFIG SHA256 `99107cb0eb989d1381321f560664c78bf4b47ebdecb2cc33e9a7d430e1e973c4`. It also **refuses to infer dynamic root results from a static artifact**.

## Four tasks and results

| Requested task | Status | What is proven | What is still missing |
|---|---|---|---|
| **1. Demonstrate a real UAF on the phone** | **NOT DEMONSTRATED** | Exact original C431 kernel contains wrong-task proxy-lock cleanup and the actual direct caller; owner showed normal PI-futex and invalid early PI-requeue app calls | Live evidence that the vulnerable rollback or dangling-pointer lifetime actually occurred on the handset. The earlier invalid-address `EINVAL` test cannot provide this evidence |
| **2. Demonstrate stack reuse and controlled memory** | **NOT DEMONSTRATED** | Signed original ARM64 yields an **80-byte conditional arithmetic intersection** if two syscall paths begin at a common kernel stack origin | Proof of same actual reused stack origin, corresponding live object lifetime, and controlled bytes at the relevant freed-object region |
| **3. Build a complete, build-specific C431 profile and validate its mitigations** | **PARTIAL** | Original kernel identity, several signed struct fields, inlined waiter position, call graph and hardening configurations confirmed; `CONFIG_CFI_CLANG=y`, `CONFIG_CFI_PERMISSIVE=n`, `CONFIG_RANDOMIZE_BASE=y`, `CONFIG_VMAP_STACK=y` | Remaining exact build geometry and runtime conditions. Earlier candidate profile still contained missing fields and a host-derived `kernel_phys_load` value not valid for the phone |
| **4. Reproduce temporary root** | **NOT DEMONSTRATED** | No credible phone-specific root proof exists in these artifacts | Reproducible on-device elevation verified for the exact model/build/kernel. Even then permanent bootloader unlocking would remain a separate secure-boot/Keymaster question |

**Therefore the four tasks are not completed simply because their static prerequisites are found.** Calling the port “working” would be unsupported.

## Public research crosscheck

- [MSEDGE-CORE/GhostLock-HonorFne](https://github.com/MSEDGE-CORE/GhostLock-HonorFne) is documented for different Chinese HONOR and device-specific releases. Its public `root/exploit/src/core/target.h` contains nonmatching task/waiter geometry, and no exact matching entry for `5.4.295-qgki-ga2d8945339ca` was found in the public search performed for this report.
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) demonstrates that **vulnerable code alone is not equivalent to a feasible pselect stack-reuse exploit**; per-build layout and compiler optimizations can prevent the method.
- The [official GhostLock advisory](https://access.redhat.com/security/vulnerabilities/RHSB-2026-010) confirms the class of local privilege-escalation risk, not a root result for this C431 build.

## Completed work

- New [fail-closed four-task grader](../tools/audit_c431_ghostlock_four_remaining_tasks.py).
- New [12 positive and negative regression tests](../tools/test_audit_c431_ghostlock_four_remaining_tasks.py).
- New [GitHub Actions integration](../.github/workflows/audit-c431-ghostlock-four-tasks.yml) using exact prior signed-firmware artifacts.
- Output artifact `HONOR70_C431_GHOSTLOCK_FOUR_TASK_EVIDENCE_STATUS` containing JSON status and a CI summary, available under [run 43291260101](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43291260101).

**No exploit payloads, no active vulnerable futex races, no kernel writes, and no device/EDL operations were performed.** This research narrows the exact evidentiary gap but does **not** claim to have completed all four required tasks.
