# HONOR 70 FNE-NX9 (MagicOS 8.0.0.290) — detaljna kontrolna tačka posle Board poređenja

**Datum:** 9. novembar 2026.
**Uređaj:** HONOR 70 FNE-NX9 (EEA C431), FNE-N29 8.0.0.290(C431E4R3P1), Qualcomm SM7325, UFS.
**Cilj:** reproduktivan *trajni* unlock bootloadera, ne FRP reset ili privremeni root.
**Trenutni rezultat:** UNLOCK **NIJE** POTVRĐEN. Nijedan korak u ovom dokumentu nije izvršen na fizičkom telefonu niti je obavljeno flešovanje.

## Zašto konvencionalne putanje nisu dovele do uspeha

Android je prijavio `sys.oem_unlock_allowed=1`, ali Fastboot/AVB su ostali zaključani. To nisu kontradiktorna stanja: dozvola za pokušaj nije isto što i trajna promena lock-a. Iz originalnog EEA ABL-a znamo da se FRP allow bit učitava iz zadnjeg bajta `frp` particije, pa se stanje pokušava menjati pozivom `VBRwDevice` protokola. Njegov XBL provider bira između `devinfo` blok I/O i Keymaster/RPMB putanje prema SCM security-state bitovima. **Ne znamo stvarnu live SCM vrednost**, pa ne smemo zaključiti apsolutno da svaka operacija na korisnikovom uređaju ide u RPMB.

Ako zaštićena putanja koristi Keymaster, `km41.mbn` odbija standardni `READ_KM_DEVICE_STATE (0x202)` i `WRITE_KM_DEVICE_STATE (0x203)` nakon milestone, preko `qsee_is_sw_fuse_blown(1)`. Nalaz predstavlja **firmware logiku**, ne direktno merenje fuse-a na telefonu.

## Board FNE-AN00 — konkretni, ponovljivi nalazi

Paket `Honor_70_FNE-AN00_1.0.0.34_220721_HMT.zip` dobijen preko GitHub Release-a, hash/proizvodni fajlovi upoređeni sa originalnim EEA stock firmware-om.

### Originalni Fastboot unlock kod

Board `LinuxLoader.efi` SHA-256: `1b7cbcf021a929d4f0fc3deea0d5f0c6594ea1c6203da62d00dd4672f4651497`, Ghidra `flashing unlock_critical` handler `0x23B9C`:

```asm
0x23B84 mov w0, wzr ; normal
0x23B88 mov w1, #1  ; unlock
0x23B8C b #0x25F14

0x23B9C mov w0, #1  ; critical
0x23BA0 mov w1, #1  ; unlock
0x23BA4 b #0x25F14
```

Sva četiri unlock/lock i critical-lock stuba završavaju na **istoj** funkciji `0x25F14`, sa FRP permission gate-om i pozivima za promenu trajnog stanja, isto kao EEA `0x27850`. Dakle, **`unlock_critical` nije skriveni prolaz** mimo Keymaster.

[Izvor — stvarne ARM64 instrukcije i Fastboot registracija](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42607900947);
[uporedna dekompilacija](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42616465352).

### Milestone u fabričkom bootloaderu NIJE uklonjen

Board ABL poziva UEFI milestone protokol na `0x3844`:

```asm
0x3838 ldr x8,[sp,#0xa0]
0x383c ldr x0,[x8]
0x3840 ldr x8,[x0,#0x20]
0x3844 blr x8
```

EEA na `0x42A4` koristi ekvivalentan poziv. **Prisustvo callsite-a nije dokaz da ga svaka boot putanja izvršava**, ali isključuje hipotezu da Board ABL potpuno izostavlja milestone. Na Board ABL-u nema `NoAVBLoad_fw_ufsdev` ASCII stringa, dok EEA ima tri instance; oba imaju `LoadImageAndAuthVB2`. To **ne dokazuje** odsustvo svake NO_AVB funkcije, ali ne podržava jednostavan Qualcomm GPT-vbmeta bypass iz javnog Redmi PoC-a.

[Izvor — verifikovano identični unutar firme potpisani UEFI fajlovi i ARM64 segmenti](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42618309888).

### XBL VerifiedBootDxe izvršni kod je identičan

Board i EEA `VerifiedBootDxe` PE sekcija `.text` (49.152 bajta, RVA 0x1000) imaju identičan hash:
`201e99c3edcd4b70969c35fabd060a9e2629e134677e8bc2a1de5640391e6e39`.
Njihove `.data` sekcije se razlikuju. Identitet koda snažno govori da je backend selector isti, **ne** da je svaka konfiguracija/bezbednosno stanje isto.

[Izvor — poređenje sekcija](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42607301965).

### Keymaster WRITE skoro potpuno isti, preostala razlika u adresama labela

Board `WRITE_KM_DEVICE_STATE` RVA `0x118790`; EEA `0x118878`.
Precizno poređenje otkrilo je da se preostale dve razlike posle normalizacije odnose isključivo na unutrašnje oznake:
`code_r0x001187d4` (Board) naspram `code_r0x001188bc` (EEA).
Proveravani uslovi i pozivi izgledaju isto, uključujući `km_check_is_sw_fuse_blown`; Board nije dokazano manje restriktivan.

[Izvor — potpuni 2-strani diff Ghidra koda](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42619245652).

### Dva programera: stvarno različit izvršni kod, isti klasični Firehose interfejsi

`prog_firehose_ddr.elf` i `prog_firehose_lite.elf`: svaki po 954.208 bajtova, ali 418.933 različitih bajtova kroz 34.051 blokova, različite `PT_LOAD` `RX` sekcije. Nisu dva potpisa istog izvršnog koda i ne treba ih neprovereno zamenjivati.

U originalnim stringovima postoji obrada standardnih `read`, `program`, `erase` i UFS komandi, plus `UFS LU Write Protect` / `RPMB ReadWrite Size`. **Stringovi sami po sebi nisu dokaz da loader radi na tvom telefonu, da su sve naredbe dopuštene, niti da postoji RPMB ključ**.

[Izvor — programer capability strings](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42618381995);
[DDR vs Lite ELF segmenti](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42618766739).

### `patch_avb.img` i Board GPT nisu unlock

`patch_avb.img` je 2.158.740 B Android sparse -> 128 MiB ext4 sa oznakom `patch_hn`, prazan root izuzev `lost+found`, AVB metapodatak pri kraju slike. Nije potvrđen bootloader unlock patch.

Board i EEA GPT za 5/6 UFS LUN-ova imaju isti raspored; LUN0 Board ima manje `super` i dodatni `flash_ageing`. **Ne primenjivati ceo Board GPT niti priloženi `download_for_7325_v1.0.bat`**: script ima stvarne UFS brisanje komande, ne samo serviranje firmware-a.

[Izvor — AVB struktura](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42616995892);
[GPT poređenje](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42606351625).

## Nezavisne javne potvrde — granice

- **Octoplus Huawei Tool v1.3.5, 08.08.2024:** potvrđuje Qualcomm loader za Honor 70 FNE-NX9/FNE-AN00; *Unlock Bootloader* su odvojeno navedeni za Huawei P60 Pro i Mate 50, ne FNE-NX9. https://octoplusbox.com/en/news/octoplus-huawei-tool-v-1-3-5-is-out/
- **GSMForum.ru, 23.12.2025:** serviser je uočio da inženjerski Board boot može ukloniti OEMINFO read-only region; flešovanje samo EDL dela Board-a mu **nije otključalo bootloader**, a Fastboot deo nije završio. https://gsmforum.ru/threads/chipset-sm7325-honor-70-fne-nx9-vykladki-po-pitaniyu.349600/
- **Qualcomm originalna dokumentacija:** RPMB je zasebna UFS bezbednosna oblast, nije običan blok koji se menja kopiranjem GPT/FRP podataka. https://docs.qualcomm.com/bundle/publicresource/topics/80-70015-11
- **Qualcomm AVB bypass PoC:** uspeo na Redmi 14R gde ABL dinamički bira NO_AVB kada nema `vbmeta` GPT; nije potvrđen na ovom HONOR 70, naročito ne na Board kompilaciji koja nema pronađeni `NoAVBLoad_fw_ufsdev` string. https://github.com/atlas4381/qualcomm_avb_exploit_poc

## Prvi nedostajući *dinamički* dokaz

Potrebna je live read-only Fastboot provera na stvarnom FNE-NX9, jer bez nje nije pouzdano razlučeno:
- ABL `get_unlock_ability=0` i Android `sys.oem_unlock_allowed=1` -> FRP flag sinhronizacija/politička razlika;
- ABL `get_unlock_ability=1` ali `unlocked=no` -> fokus na upis/persistenciju UEFI/Keymaster state-a i rezultat stvarne prethodne potvrde;
- `FAILED (remote: 'Command not allowed')` čak i za nedestruktivan `flashing get_unlock_ability` -> aktivni Fastboot handler/komandna registracija se razlikuju od analiziranog signed release-a ili servisna politika blokira komandu;
- `is-userspace=yes` -> trenutno je `fastbootd` umesto ABL bootloadera, rezultati se ne mogu direktno porediti.

Ovim povodom napravljen je [testiran bezbedan Windows read-only Python dijagnostički alat](https://github.com/PetarM09/honor70-firmware-analysis/blob/main/tools/honor70_fastboot_lockpath_readonly.py), koji **ne pokreće** `flashing unlock`, `flash`, `erase`, `format`, `oem unlock` ni exploit. Može po izričitom izboru korisnika prebaciti telefon iz Androida u Fastboot i nazad bez izmene korisničkih podataka. [CI test na simuliranom bootloaderu](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42619084279).

Na Windows-u kada su ADB i Fastboot već instalirani (i telefon povezan USB debugging režimom):

```powershell
cd "$env:USERPROFILE\Downloads"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PetarM09/honor70-firmware-analysis/main/tools/honor70_fastboot_lockpath_readonly.py" -OutFile "honor70_fastboot_lockpath_readonly.py"
py -3 .\honor70_fastboot_lockpath_readonly.py --enter-fastboot --reboot-at-end
```

Zatim dostaviti samo `HONOR70_FASTBOOT_LOCKPATH_READONLY.txt`. U izlazu se ne štampa serijski broj uređaja; dodatna redakcija podataka je dobra praksa.

**Ne preporučuju se** Firehose `program` / `erase`, EDL režim test-point kontaktima, ceo Board `rawprogram.xml`, manipulacije `frp`, `oeminfo`, `devinfo`, `vbmeta` ili ponovno izvršavanje destruktivnog Fastboot unlock komanda dok ne bude poznato šta telefon aktivno vraća i šta može da se oporavi.
