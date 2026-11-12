# 2026-11-12 — Three concurrent signed-firmware research workers and Fastboot early-exit correction

**Device:** HONOR 70 FNE-NX9, European C431 MagicOS 8.0.0.290.

**Verification:** [Successful GitHub Actions run 43126930044](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43126930044) executed **three independent concurrent jobs** in a `strategy.matrix`, `max-parallel: 3`, `fail-fast: false`. All three completed successfully.

> The jobs are deterministic source-asserted analysis workers, **not** independent generative AI agents. They cannot infer live device data or act beyond the source evidence. The workflow never accesses, flashes or modifies the phone.

- Source tool: [`tools/parallel_unlock_research.py`](../tools/parallel_unlock_research.py)
- Workflow: [`.github/workflows/parallel-unlock-research.yml`](../.github/workflows/parallel-unlock-research.yml)
- Worker artifacts: `HONOR70_PARALLEL_UNLOCK_abl`, `HONOR70_PARALLEL_UNLOCK_xbl`, `HONOR70_PARALLEL_UNLOCK_km`, 30-day retention.
- Exact input report digests: ABL `337c8274cb5edb42ce17142f0291b6810b03076b49b844c9b9dfdfc9acaecbc7`, XBL `a00112cdc87e8dbe6a6605a597dd62eefcde84a8d7f443160712d55b745e6ef7`, KM41 `5137eeceb492e0cdc915308bd8950b7343421b62f1954e7ab267ed6ca1fd9fb2`.

## Worker A — stronger negative finding: normal Fastboot pre-check exits before confirmation/setter

The original signed EEA ABL, SHA256 `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087`, contains this *earlier* check in Fastboot `FUN_00027850`:

```asm
0x2788c bl   #0x433a8  // wrapper around local getter 0x13008
0x27890 and  w8, w0, #0xff
0x27894 cmp  w8, w21, uxtb  // current logical state vs request
0x27898 b.ne #0x278b8       // if different, continue unlock path
0x2789c bl   #0x27f64       // otherwise compose Device already response
...
0x278ac bl   #0x27b18
0x278b4 b    #0x278d8       // response and exit
...
0x279d0 bl   #0x3dab8       // optional physical UI path, only in different-state branch
0x279ec bl   #0x43688      // direct setter path after permissions, only if prior check differed
```

Original `0x433A8` function at `0x433AC` calls the same `FUN_00013008` logical state getter, and returns immediately. Since the actual normal unlock request is byte `1`, the **normal Fastboot command cannot simultaneously pass this earlier not-equal check and then immediately take the setter's equal-state shortcut under an unchanged context**. A change to local state between calls, or a different entry point, would be an additional hypothesis requiring evidence.

The physical confirmation callback `0x3D9B8` is a distinct layer: at `0x3D9E0` it first issues a `VBRwDevice READ`, then at `0x3DA5C` calls `FUN_00043688` using the original UI descriptor table. **Do not mistake a `Device already` or a wipe for a persistent secure-state unlock.**

**This further reduces the likelihood that the historical wipe+LOCKED event was caused by the ABL setter's equality shortcut.** It does **not** prove which path the old attempt took.

## Worker B — XBL protected read-before-write and SCM selection confirmed

Original `VerifiedBootDxe` decompilation, based on SHA256-pinned PE `f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55`:

- Original secure selector `(SCM_security_state & 0x8703)==0` chooses Keymaster/RPMB.
- `VBRwDevice WRITE` first sends `READ_KM_DEVICE_STATE (0x202)` and checks both QSEE transport success and response status. It sends `WRITE_KM_DEVICE_STATE (0x203)` **only after this read succeeded**.
- On a failed preread, the fallback policy uses mask `0x8723`. The sole mask difference is `0x20`. This is only a branch class, **not** an evidenced hardware bypass or tested live SCM value.
- The possibility of direct `devinfo` storage on an entirely different SCM class does not mean EDL partition writes affect secure persistent lock state.

## Worker C — KM41 milestone fuse gate reconfirmed

Original European signed Keymaster `km41.mbn` SHA256 `c7f389b80444a9c9e3956efd427abbae1b5b2753b3c905107ca7888dca496afd`:

- `READ_KM_DEVICE_STATE (0x202)` callback `0x1185A8`.
- `WRITE_KM_DEVICE_STATE (0x203)` callback `0x118878`.
- Both reference common `0x117980`, which invokes `qsee_is_sw_fuse_blown(1)`.
- `MILESTONE_CALL (0x204)` is separately dispatched to `0x117A18` and references an actual software fuse-blow operation. **Do not invoke it experimentally.**
- No live fuse value has been measured, no historical `0x202` response tied to the original Fastboot UI, and no confirmed successful `0x203` on that handset.

## Practical hypothesis ordering (evidence, not probabilities)

The highest-value unresolved issue is which **protected preread/backend gate** ran during the original unlock attempt:

1. ABL Fastboot dispatch and local state early comparison: the static branch logic is now established, but the owner's old transcript is absent.
2. ABL confirmation callback performs an initial `VBRwDevice READ` before the state setter. No historical callback status is captured.
3. XBL's SCM selector chooses the actual persistent backend. The device's live SCM state is not known.
4. In secure mode the Keymaster fuse gate can block `0x202`; if the preread fails, no `0x203` follows. The exact live error code is unmeasured.
5. The later `DELETE_ALL_KEYS (0x10E)` and recovery wipe are separate from the protected state write; neither proves a successful unlock.

## Public-method crosscheck (as of 12 November 2026)

- [Official HONOR 70 support](https://www.honor.com/global/support/phones/honor-70/) identifies the model but does not publish a confirmed unlock procedure for FNE-NX9.
- [Octoplus Huawei 1.3.5 release notes](https://octopusbox.com/eng/news/details/1031) list Honor 70 under **supported Snapdragon loaders**, but list **Unlock Bootloader** as a feature for different named Huawei models, **not for Honor 70**. EDL-loader support must not be mistaken for bootloader-unlock support.
- [UnlockTool model matrix](https://www.unlocktool.me/supported-models) lists FNE-AN00/FNE-NX9 with FRP, flashing and OEMINFO functions; it does **not** visibly list a confirmed `Unlock Bootloader` action for Honor 70. No guarantee can be inferred.
- Generic Huawei IMEI/brute-force unlock-code tools targeting older pre-2020 models do not provide a validated route for this Snapdragon FNE-NX9 MagicOS 8 firmware.

This comparison is limited to cited source descriptions; no service-tool license, loader or access was tested.

## Next experiments that are justified

Continue **read-only** static correlation of the stock XBL SCM selector and KM41 response statuses, and examine existing historic logs if an actual Fastboot UI transcript is already present in the repository. Do not force SCM flags, flash Board ABL/XBL, alter OEMINFO/FRP/devinfo, or run the destructive unlock command solely to obtain logging.

**Bottom line:** no verified permanent unlock method yet. The three genuinely parallel jobs ran successfully and narrowed the remaining gate; they did not invent a method or modify the device.
