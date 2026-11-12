# 2026-11-12 — Firehose `peek/poke`: runtime security query and original XML command-token evidence

**Device research:** HONOR 70 FNE-NX9 C431 MagicOS 8.0.0.290, offline code audit of **signed HMT FNE-AN00 Board** Firehose candidates. No on-device interaction, no bootloader unlock.

## Reproduced evidence

- [Signed parallel DDR/Lite Ghidra decompilation](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43136649865) — two successful jobs
- [Selected original Ghidra function bodies](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43136830889) — two successful jobs
- [NUL-delimited XML command tokens vs embedded diagnostic substrings, with assertions](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43137433674) — two successful jobs
- [Original ELF / exact-token verifier](../tools/audit_firehose_peekpoke_registration.py)
- [Original Ghidra code extractor](../tools/ghidra/Honor70FirehosePeekPokeGuardAudit.java)

Original signed ELF SHA256:
- DDR `9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8`
- Lite `e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101`

### Verified Secure Boot query

Both programmers contain `FUN_1482011C`:

```c
void FUN_1482011c(unsigned int *result) {
    *result = 0;
    FUN_1483d97c(0x82000119, 1, 1, 0, 0, 0, 0, local_38);
    if (local_38[0] == 1) *result = 1;
}
```

This is a Qualcomm secure-monitor call (SCM-style invocation) queried at runtime. Confirmed caller `FUN_1481FCCC` uses the result for the `Secure Boot:` status line. **This does not prove the same result is consulted inside an XML `peek` or `poke` command permission handler**; those handlers have not been positively located in either signed programmer.

### Crucial string false-positive resolved

Both exact signed Firehose binaries contain an adjacent original command-token string cluster at raw ELF offsets `0x774B1`–`0x77504`. Exact NUL-delimited standalone command identifiers include:

```text
program\0 read\0 nop\0 patch\0 configure\0 setbootablestoragedrive\0
erase\0 getstorageinfo\0 ...
```

The standalone **`peek\0` does not occur anywhere in either signed ELF**. The only apparent `poke\0` occurrence is at file offset `0x775F7`, **preceded by ASCII slash `/`**, inside the longer diagnostic message:

```text
size in bytes is %d, nothing to peek/poke\0
```

Thus the `poke\0` match is **not an independent command string**. Neither ELF contains an independent NUL-delimited `peek` or `poke` token under the same verification that successfully finds normal storage command tokens. Also, literal strings `Peek is disabled on secure boot devices` and `Poke is disabled on secure boot devices` were found **without direct relocatable pointer references** in the program and without a proved direct ADRP+ADD code reference in the earlier signed ARM64 xref audit. This strengthens the conclusion that those message strings alone cannot establish a reachable memory-command handler.

**Conservative conclusion:** no positive evidence of registered memory `peek/poke` commands or successful protected RAM read/write in either original Board programmer. String absence is not a formal whole-program proof (optimized or indirect dispatch is possible). No device-specific runtime capability test has been performed.

### Important unrelated functions that would be easy to misidentify

The targeted Ghidra analysis also proved:
- DDR `FUN_14824298` is a C `printf`-style formatting engine, **not `peek/poke`**.
- DDR `FUN_14825120` is a `getsha256digest` **storage-sector hashing** handler, not arbitrary RAM read.
- DDR `FUN_14825DBC` performs UFS-sector `patch` operations using read/write of block sectors; not TrustZone memory patching.
- DDR `FUN_1482BC3C` only prints `getstorageinfo` UFS descriptors, including the `UFS RPMB ReadWrite Size` field; not an authenticated RPMB writer.

### Impact on permanent unlock plan

The signed Firehose tools support ordinary authenticated-loader storage operations, but we still lack **any** evidenced primitive able to:
1. write to protected Keymaster/RPMB lock state `0x203`;
2. bypass Keymaster milestone fuse gate;
3. safely execute arbitrary code in the Secure Boot trust chain;
4. induce permanent `UNLOCKED` on the exact retail FNE-NX9.

**Do not interpret a string occurrence or EDL `patch` success as any of these.** There is no sound reason to issue unverified `peek/poke` commands or write the GPT/ABL/XBL/FRP/OEMINFO based on this finding. Research can continue through executable XML dispatch analysis or a verified signed FNE-NX9-specific engineering firmware.

No live EDL session was used and no persistent unlock method was reproduced in this investigation.
