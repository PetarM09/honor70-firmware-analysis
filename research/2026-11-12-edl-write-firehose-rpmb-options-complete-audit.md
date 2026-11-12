# 12.11.2026 — HONOR 70 FNE-NX9: EDL WRITE, Firehose, RPMB i ozbiljne unlock opcije — provereni dokazi

**Uređaj:** FNE-NX9, C431E4R3P1, MagicOS 8.0.0.290, Snapdragon SM7325 / UFS.  
**Status:** **nema dokazane, reprodukovane metode trajnog bootloader unlock-a**. Originalni potpisani EEA i Board binarni fajlovi analizirani su offline, bez novih upisa na fizički telefon u ovoj sesiji.

**EDL write je eksplicitno razmotren.** EDL omogućava određene normalne UFS izmene, ali te izmene ne znače da će Secure Boot prihvatiti novi bootchain ili da se promenio zaštićeni Keymaster/RPMB lock state.

## Novi rezultati — originalna dva potpisana Board Firehose programera

Originalni FNE-AN00 HMT paket i tačan SHA-256:

| Programer | SHA-256 | Bajtova |
|---|---|---:|
| `prog_firehose_ddr.elf` | `9c892e716320764c20055d8374bf8eca7418b3ff2177f81794e18d3656fc55a8` | 954208 |
| `prog_firehose_lite.elf` | `e029df6e2d532de87c2279e960472ec0e4799aca53bc27ed4fa3e4027b05d101` | 954208 |

1. [Source-pinned SHA256/ELF/command-string audit, run 43134342642](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43134342642) — **SUCCESS**.
2. [Dva paralelna Ghidra posla, run 43134581030](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43134581030) — **oba SUCCESS**.
3. [ARM64 kodni xref audit, run 43135236599](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43135236599) — **oba SUCCESS**.
4. [Originalni Ghidra dekompajlirani konteksti, run 43135436197](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43135436197) — **oba SUCCESS**.

### 1. RPMB: originalna poruka ne dokazuje WRITE

Oba originalna programera sadrže tekst:

```text
UFS RPMB ReadWrite Size: = 0x%x
```

ARM64 kodni xref vodi do DDR `0x1482BD2C` u `FUN_1482BC3C` (Lite funkcija je pomerena). Ghidra dekompilacija pokazuje da ta funkcija **redom ispisuje** `UFS Current LUN Number`, `UFS Total Active LU`, `UFS Raw Device Capacity`, `UFS RPMB ReadWrite Size`, `UFS LU Write Protect`, `UFS Boot LUN ID` i ostala polja iz jednog UFS descriptor strukture. To je rutina za *storage-info dijagnostiku*, ne implementacija `READ_KM_DEVICE_STATE (0x202)` niti `WRITE_KM_DEVICE_STATE (0x203)`.

**Šta nije dokazano:** da Firehose ume da čita/piše autentifikovane RPMB sektore, da zna RPMB ključ ili da može da pozove Keymaster komandu. Isti string u programu nije takav dokaz.

### 2. `patch` nije proizvoljna memorijska zakrpa

Originalna DDR rutina `FUN_14825DBC`:

- loguje `patch command is deprecated`;
- parsira `filename`, `SECTOR_SIZE_IN_BYTES`, `start_sector`, `byte_offset`, `size_in_bytes`, `value`;
- ograničava veličinu patch vrednosti na ispod 9 bajtova;
- čita ciljane sektore kroz `FUN_148298E0(...)`;
- menja bafer;
- upisuje isti sektor kroz `FUN_14829948(...)`.

To jeste **EDL WRITE primitiva za običnu UFS lokaciju**, ali nije dokaz proizvoljnog RAM `poke` pristupa, pisanja u zaštićeni RPMB ili izmene izvršavanja već autentifikovanog ABL/Keymaster koda.

### 3. `peek` i `poke`: Secure Boot poruke postoje, uspešan memory access nije potvrđen

Oba originalna programera sadrže potpuno iste:

```text
Peek is disabled on secure boot devices%c
Poke is disabled on secure boot devices%c
```

Potvrđene su adrese stringova i originalni SHA256; međutim Ghidra i direktni ARM64 ADRP/ADD pregled nisu još povezali obe poruke sa **potpuno dokazanim izvršivim permission uslovom**. Stoga je najprecizniji zaključak: programeri imaju poruke o Secure Boot zabrani ovih komandi, ali njihova stvarna dostupnost na telefonu nije izmerena. Nemamo opravdanje za pretpostavku da je `poke` prihvaćen u zaključanom uređaju.

### 3a. Naknadno dokazano: stvarna XML tabela ima 15 komandi, bez peek/poke

[Direktna analiza oba potpisana ELF-a](2026-11-12-signed-firehose-15-command-xml-dispatch-no-peekpoke.md) i [uspešna nezavisna verifikacija](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43137871278) potvrdile su **15 parova pokazivača na ime komande i ARM64 handler** u tabeli koja počinje na `0x148A2968`. Registrovane su uobičajene `program`/`read`/`patch`/`erase` i specijalne `firmwarewrite`/`fixgpt`, ali **nema XML `peek` ni `poke` entry-ja**. Jedini potencijalni `poke\\0` je završetak rečenice `nothing to peek/poke\\0`, ne zasebna komanda.

Oba programera koriste `FUN_1482011C`, koji poziva Qualcomm SCM-style `0x82000119` i proverava sigurnosni rezultat; dokazan je njegov pozivalac koji ispisuje `Secure Boot:`, ali ne i bilo kakav legitiman RAM `poke` handler.

[Potpisani DDR i Lite `firmwarewrite`/`fixgpt` handleri](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/43138463218) takođe su dekompajlirani: `firmwarewrite` predaje primljeni firmware blob **storage-device firmware update** rutini, dok `fixgpt` poziva reparaciju GPT po UFS LUN. Nema direktnog Keymaster `0x203` poziva u dekompajliranim handlerima i nema dokazanog permanentnog unlock efekta.

### 4. Dodatni servisni indikatori u originalnom programeru

Ghidra funkcija `FUN_1481FCCC` prikazuje identifikatore:

```text
QC_IMAGE_VERSION_STRING=BOOT.MXF.1.0-00863-LAHAINA-1
OEM_IMAGE_VERSION_STRING=,FACTORY_MODE,PRODUCT_FNE,FNE_ADSP
Secure Boot:
```

To su **informacije o build-u**, ne dokaz da izvršavanje sa `FACTORY_MODE` zaobilazi Secure Boot ili Keymaster milestone.

## Uslovi za realan EDL WRITE unlock eksperiment

| Opcija | Šta EDL stvarno može | Trenutni blokator za **trajni unlock** | Odluka |
|---|---|---|---|
| `devinfo` izmena | Može se vratiti pojedinačan prethodni bajt | Već isprobano na uređaju i ostaje `LOCKED`; originalni XBL u secure SCM klasi bira Keymaster/RPMB | **Ne ponavljati** |
| `frp` i OEM unlock | Standardni UFS zapis | Aktivacija dopuštenja nije zapis trajnog Keymaster lock stanja; već isprobano | **Ne ponavljati** |
| OEMINFO zapis `0x82` / RD-mode | UFS OEMINFO se može fizički menjati | originalni ABL proverava potpisani `rdmodev1` token; 0x104 je lokalni autorizacioni kontekst, ne dokaz trajnog lock bita | **Nema validnog upisa** |
| EDL `patch` | Menja bajtove na normalnim UFS sektorima | Nema write pristupa zaštićenom Keymaster RPC/RPMB stanju | **Nije unlock primitive** |
| EDL `peek/poke` | **Nisu registrovane u izvornoj XML tabeli od 15 komandi** | Tekstovi o zabrani su prisutni, ali bez standardnog XML handlera; mogućnost indirektnog dispatch-a nije potpuno isključena | **Nema podržanog standardnog RAM peek/poke testa** |
| GPT preimenovanje `vbmeta` | Moguća izmena particione tabele | Za HONOR nije potvrđeno dinamičko `Is_VERIFIED_BOOT_2()` prebacivanje; postojeći `NoAVBLoad_fw_ufsdev` je **post-milestone UFS updater** | **Bez dokazivog cilja, visok brick rizik** |
| Board FNE-AN00 ABL / XBL | Potpisani binarni image možda se može fizički upisati | Retail i Board `VerifiedBootDxe` imaju identičan kod, Keymaster read/write/fuse gate gotovo identičan, Board ABL i dalje proverava unlock uslov | **Nema dokazivog bypass-a** |
| Native `FNE-NX9-BD` Board | Tačan inženjerski paket postoji kao komercijalni zapis | Sadržaj/potpisi/antirollback nisu dostupni za proveru; nije pronađen reprodukovan permanentni unlock | **Vredi analizirati samo ako se dobije autentičan paket** |
| Direktan RPMB lock-state write | Pravi target za zaštićenu klasu | Nema dokaza da originalni Firehose ima autentifikovani write ili OEM autorizacioni ključ | **Trenutno nema primitive** |
| Signed Keymaster `0x202/0x203` | Prava secure API putanja | Milestone `qsee_is_sw_fuse_blown(1)` na obe rutine, živa vrednost nepoznata; XBL prvo zahteva uspešan READ | **Potrebno stvarno runtime stanje ili dokazan TEE propust** |
| Fastboot CVE-2026-24091/24092 | Postoje javne CVE, ne potvrđen HONOR exploit | display handleri nisu dostupni preko zaključanog allowlista; sumnja na pre-gate 64-byte OOB je **opovrgnuta** 16 MiB USB alokacijom | **Nema validne ulazne exploit putanje** |
| Zamena potpisanog ABL/XBL izmenjenim kodom | EDL može eventualno fizički upisati image | Boot-time Qualcomm/HONOR provera potpisa i antirollback ga mogu odbiti | **Bez ključa ili exploita nema dokazanog secure-boot bypass-a** |

## Novi izvor iz serviserske prakse (nezavisno od binarne analize)

[SM7325 HONOR 70 FNE-NX9 serviserska diskusija (23–24.12.2025)](https://gsmforum.ru/threads/chipset-sm7325-honor-70-fne-nx9-vykladki-po-pitaniyu.349600/) sadrži iskustvo tehničara: korisnički firmware nameće OEMINFO read-only politiku; boot Board firmware-a menja tu politiku privremeno, ali se vraća po vraćanju korisničkog firmware-a. EDL Board deo nije otključao njegov bootloader. **To je iskustvo trećeg lica, nije test tvog uređaja.**

Isti izvor navodi UART TX tačku, ali potom posebno beleži da **UART log na korisničkom firmware-u nije dostupan**. Zato UART nije sigurna prečica za dobijanje retail Keymaster failure trace-a; ne preporučuje se nasumično priključivanje kablova na neidentifikovane padove.

## Provera servisnih alata i javnog exploita (12.11.2026)

- [UnlockTool model lista](https://www.unlocktool.me/supported-models): za FNE-NX9 navodi FRP, testpoint flash, factory reset, auth flash, change/backup OEMINFO; **ne navodi jasno proverenu operaciju Bootloader Unlock**.
- [Octoplus 1.3.5](https://octopusbox.com/eng/news/details/1031): navodi HONOR 70 među Qualcomm loader modelima, ali „Unlock Bootloader“ samo za druge Huawei modele.
- [Qualcomm public GPT/Keymaster PoC](https://github.com/atlas4381/qualcomm_avb_exploit_poc): dokazan na Redmi 14R, ne HONOR 70.
- [Model-specifičan FNE-NX9-BD komercijalni zapis](https://www.martview-forum.com/threads/latest-update-halabtech-support-20-5-2024-part-4.107007/): postoji, ali njegova dostupnost ne znači da se poklapa sa retail secure boot politikom.

## Najstroži, proverljivi naredni uslov pre upisa

Za **novi** upis koji ima smisla mora postojati bar jedan od ovih dokaza:

1. Potvrđeno da originalni potpisani Firehose na **konkretnom uređaju** poseduje privilegovanu, autentifikovanu RPMB/QSEE-state write operaciju (ne samo UFS `program/patch`).
2. Verifikovan originalni, model-specifični OEM-signed inženjerski bootchain koji **i dalje butuje posle napuštanja Board režima** i čiji secure-state put može da snimi unlocked stanje uprkos Keymaster milestone zaštiti.
3. Reprodukovan model/build-specifičan exploit koji zaobilazi prethodni Fastboot gate i daje trajno ispravan secure lock state bez falsifikovanja nepovezanih UFS particija.

U odsustvu ovih dokaza, **novi GPT/ABL/XBL/Keymaster write nije eksperimenat sa jasnim unlock predviđanjem nego nasumično oštećenje**. Rani fizički eksperimenti su već pokazali da UFS `devinfo` i FRP/OEM toggle ne čine FNE-NX9 trajno otključanim.

**Status na kraju rada:** svi navedeni offline poslovi uspešno završeni; nijedna nova fizička komanda, EDL write ili bootloader unlock nije izveden; **LOCKED** ostaje poslednje poznato stvarno stanje uređaja.
