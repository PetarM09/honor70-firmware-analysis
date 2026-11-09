# HONOR 70 FNE-NX9 — EDL laboratory tool

This is a staged research harness for a **personally owned** Honor 70 running FNE-N29 MagicOS 8.0.0.290. It **does not unlock** the device by itself, and cannot bypass signed loader authentication, Secure Boot, Keymaster, antirollback or RPMB.

The researcher has a Chinese **FNE-AN00** HMT Board archive with two candidate signed Firehose programmers, `prog_firehose_ddr.elf` and `prog_firehose_lite.elf`. Those have NOT been validated on the current FNE-NX9. The SHA256 fingerprints that the script recognizes are from the previously audited user-supplied Board package; recognizing a hash does not validate target compatibility.

## Install on a Mac

Follow the upstream [bkerler/edl installation](https://github.com/bkerler/edl#macos):

```bash
brew install libusb git
git clone https://github.com/bkerler/edl.git "$HOME/Downloads/edl"
cd "$HOME/Downloads/edl"
git submodule update --init --recursive
python3 -m pip install .
```

Depending on your Python environment, you may need to create a virtual environment instead of installing globally. See upstream docs. Obtain an unmodified signed loader from the Board package and verify its integrity. No generic loader should be substituted blindly.

The phone must *actually* enumerate in Qualcomm **9008 EDL mode**. From an Android terminal connection, `adb reboot edl` is sometimes supported, but not guaranteed on this device; do not short unidentified hardware test points. If it fails, restart normally.

## Stage 1 — probe (never writes)

```bash
python3 honor70_edl_lab.py --loader "$HOME/Downloads/prog_firehose_ddr.elf" inspect
```

If the loader is accepted, the script runs `edl printgpt --memory=ufs --loader=...` and verifies that `frp`, `oeminfo`, `devinfo`, `abl_a` and `xbl_a` appear in the actual UFS GPT. Outputs: `HONOR70_EDL_LAB/gpt_probe.json` and `gpt_probe.log`. It will **not** send any flash/erase operation during inspection.

## Stage 2 — backup before any write

```bash
python3 honor70_edl_lab.py --loader "$HOME/Downloads/prog_firehose_ddr.elf" backup
```

The script reads selected existing partitions and stores unmodified local binary backups and SHA256 manifest. These backups may include unique device identifiers or security material: **do not upload raw images publicly**. Do not assume that a backup guarantees recovery if the programmer is later rejected.

## Stage 3 — optional actual EDL flash (NOT yet recommended)

The tool supports a real single-partition `edl w` operation, but it is gated behind an existing verified local backup, a fresh on-device hash comparison, a replacement image with explicit SHA256, a named partition verified in GPT, and **two explicit authorization parameters**.

Invocation intentionally omitted until a signed image and target partition have been selected through research: do **not** flash an arbitrary Board ABL, XBL, GPT, FRP, OEMINFO or devinfo dump. EDL write success is not the same as accepting the image at boot or unlocking Keymaster's protected state.

If no compatible signed programmer is available, stages 1/2 cannot succeed. That is an important negative result, not proof that an EDL write method exists.

## Inspect devinfo before making an unlock experiment

After `backup`, run:

```bash
python3 inspect_devinfo_backup.py HONOR70_EDL_LAB/backups/devinfo.img
```

This prints only the magic's offsets and a few possible status bytes, **not** a personal partition dump. Note that `ANDROID-BOOT!` structure layouts vary among Qualcomm firmware versions. In the exact EEA ABL, two nearby state values are written via the Verified Boot protocol, which may use Keymaster/RPMB rather than this normal partition. Do **not** patch bytes from unrelated guides before confirming the exact active storage backend.

### Access original programmer ZIP without redownloading 2.57 GB

The user-owned GitHub Actions run https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42553239190/artifacts/13646301497 contains `selected_bootchain.zip` with `bootloaderimage/prog_firehose_ddr.elf` and `prog_firehose_lite.elf`. Verify the SHA256 after extraction; these programmer files have not yet been accepted by the physical EEA phone.
