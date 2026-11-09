# HONOR 70 FNE-NX9 — zaključak o bootloader unlock putanjama (9.11.2026)

**Ciljni uređaj:** HONOR 70 FNE-NX9 EEA, `8.0.0.290(C431E4R3P1)`, Android 14; kernel `5.4.295-qgki-ga2d8945339ca`.

**Status:** NEMA potvrđenog, reproduktivnog postupka za trajni bootloader unlock na ovom uređaju. Ovaj izveštaj **nije** skripta za otključavanje. Sve dole navedene provere rađene su statički nad originalnim, potpisanim firmware-om i/ili preko dozvoljenih ADB čitanja, bez upisa na uređaj.

## Prikaz slojeva i verifikovanih uslova

```text
Android Developer options: OEM unlocking ON
    |
    +--> PersistentDataBlockService / ro.frp.pst -> FRP poslednji bajt
    |      => sys.oem_unlock_allowed=1 (indikator, ne direktno merenje bajta)
    |
    v
ABL LinuxLoader: fastboot flashing unlock
    |  0x25c04 -> 0x27850
    |  preuzima allow bit iz FRP-a, kod 0x23fd0/0x240c8
    v
QcomVerifiedBoot UEFI protocol GUID
    8e5eff91-21b6-47d3-af2b-c15a01e020ec
    |
    v
XBL VerifiedBootDxe (sha256 f7a2778d...)
    |  RWDeviceState: FUN_0000153c
    |  secure state: SCM 0x2000604
    |  state & 0x8703 -> bira backend
    |
    +--> devinfo preko UEFI block I/O (kad konfiguracija dozvoli)
    |
    +--> QSEE "keymaster" / RPMB (sigurnosno zaštićena putanja)
             read 0x202 -> KM41 0x1185a8
             write 0x203 -> KM41 0x118878
             milestone 0x204 -> KM41 0x117a18
             |
             +--> KM41 0x117980 poziva qsee_is_sw_fuse_blown(1)
                   na aktiviranom softverskom osiguraču read/write odbijeni (−15)
```

**Zapažanje na telefonu** (priloženi read-only ADB izveštaj): model FNE-NX9, build `8.0.0.290C431E4R3P1`, `sys.oem_unlock_allowed=1`, `ro.boot.flash.locked=1`, `ro.boot.verifiedbootstate=green`, `ro.boot.vbmeta.device_state=locked`. Sistemski servisi `oem_lock` i `persistent_data_block` su vidljivi, ali standardni proizvođački `android.hardware.oemlock` HAL nije pronađen kroz dostupne VINTF i HIDL provere (negativan rezultat nije dokaz da ne postoji druga Honor autorizaciona usluga).

**Oprez u interpretaciji FRP-a:** `sys.oem_unlock_allowed=1` može biti usklađen sa poslednjim bajtom FRP-a nakon starta, ali sam ne dokazuje da je ABL na trenutnom boot-u učitao 1; direktno merenje tog bajta nije obavljeno.

## Konkretni firmware potpisi

| Modul | SHA-256 |
|---|---|
| LinuxLoader UEFI iz originalnog `abl.elf` | `ebe7d430a39e7cb4e3b882745330677ec0f1972481fd4e738d84ecdc969db087` |
| `VerifiedBootDxe` PE iz originalnog `xbl.elf` | `f7a2778d20067ebe97a4be7fdd2bb79a06456b8ddb07ab8a37c63951ec1c0c55` |
| `km41.mbn` originalni Keymaster trustlet | `c7f389b80444a9c9e3956efd427abbae1b5b2753b3c905107ca7888dca496afd` |

## Keymaster: dokazana firmware zaštita

1. Tabela starog komandnog dispečera je stvarna (proverena direktnim sirovim bajtovima `km41.mbn`):
   - `0x202` READ, flag `0x100`, callback `0x1185a8`
   - `0x203` WRITE, flag `0x100`, callback `0x118878`
   - `0x204` MILESTONE, flag `0x000`, callback `0x117a18`
2. Zasebna provera `FUN_0011b174`, kojoj dispečer pristupa kada je zastavica `0x100`, uglavnom zahteva spremnost/inicijalizaciju zaštićenog skladišta. To **nije samo po sebi dokaz milestone autentičnosti**.
3. Obe stvarne read/write funkcije **dodatno** pozivaju `FUN_00117980`, koja proverava `qsee_is_sw_fuse_blown(1)`. Kada je osigurač aktiviran, zahtevi se odbijaju sa `-15`/ `0xFFFFFFF1`.
4. `FUN_00117a18`, milestone handler, aktivira `qsee_blow_sw_fuse(1)` i potom `qsee_blow_sw_fuse(0x16)` prema rekonstruisanoj putanji.
5. Alias nazivi `KM_NEW_READ_KM_DEVICE_STATE`, `KM_NEW_WRITE_KM_DEVICE_STATE`, `KM_NEW_MILESTONE_CALL` jesu u stringovima, **ali komandni ID-jevi `0x2202`, `0x2203`, `0x2204` nisu pronađeni kao registrovani handleri u proveravanoj tabeli**. Nisu dostupna potvrđena alternativna vrata.

## ABL: milestone je stvarna funkcija, ne samo log

Kod originalnog LinuxLoader-a `FUN_00003144`, prepoznao se blok na adresama `0x4298..0x42a4`:

```asm
00004298  ldr x8, [sp, #0xa0]
0000429c  ldr x0, [x8]
000042a0  ldr x8, [x0, #0x20]
000042a4  blr x8
```

Prethodni debug string `Sending Milestone Call` nalazi se na lokaciji koja se koristi u istoj grani. Gornji kod poziva metodu UEFI protokola; njegovo pozivanje nije isto što i dokaz vrednosti softverskog osigurača na živom telefonu.

## Javna Qualcomm AVB2/NO_AVB PoC: zašto još nije primenljiva

Javni `atlas4381/qualcomm_avb_exploit_poc` potvrđen je na **Redmi 14R**, i pretpostavlja:
- dinamičku `Is_VERIFIED_BOOT_2()` proveru postojanja GPT `vbmeta`/ `vbmeta_a`;
- mogućnost pisanja GPT čak i dok je bootloader locked (EDL/privilegije);
- povratak u `NO_AVB` bez milestone, zatim odgovarajući TEE/Keymaster korisnički interfejs za state write;
- potpunu, ispravnu proceduru oporavka i kompatibilan sekundarni sistem.

U odgovarajućem originalnom **HONOR 70 LinuxLoader-u** ciljano smo proverili ASCII i UTF-16LE nazive:

- ASCII `vbmeta`: **jedna** instanca na `0xb00c6`, koristi je **AVB verifikacioni kod** (kod reference `0x70a4`, `0x7150`, `0x7970`);
- `vbmeta_a` i `vbmeta_b`: **nisu pronađeni** kao zasebni ASCII/UTF-16LE stringovi;
- UTF-16LE `vbmeta`: **nije pronađen**; UTF-16LE `frp` je, kao pozitivna kontrola, pronađen na `0xbbe26` i referenciran iz `0x23fc4`.

Oba pojma `NoAVBLoad_fw_ufsdev` i `LoadImageAndAuthVB2` nalaze se u originalnoj funkciji `FUN_00003144`, ali samo postojanje oba code path-a ne pokazuje da se između njih bira dinamički preko GPT-a. **Nije pronađen dokaz da Honor 70 radi nebezbednu GPT-dependent selekciju.** Nije definitivno dokazano odsustvo svih indirektnih metoda, ali GPT preimenovanje **nije opravdano** ovim rezultatima.

Originalni firmware GPT navodi 6 UFS LUN-ova, ukupno 135 particija, i **nema `efisp` ili `gbl`**, tako da ne može direktno da se primeni zaseban unsigned-GBL trik.

## Testovi i hipoteze — status

| Putanja | Status / blokada |
|---|---|
| Standardni fastboot `flashing unlock` | U istoriji testa izazvao wipe/prompt, ali ostao `LOCKED`; razlog neuspešne tranzicije i status aktivnog runtime state-a nisu dokazani |
| OEM unlocking toggle | Android property =1; ne znači persistent unlocked |
| OEMINFO 95/130 | HAL čita/piše određene bitove; mapiranje/uticaj na pravi UEFI Keymaster state nije dokazano; pisanje izuzetno rizično |
| Direktno `devinfo` | UEFI driver ga podržava uslovno, ali secure-backed putanja može da ga isključi |
| Keymaster RPMB | Stvaran milestone fuse gate u read i write funkcijama; živo stanje osigurača nepoznato |
| Novi KM komande `0x2202/3/4` | Nazivi postoje; u registrovanoj tabeli nema dokaza da se mogu pozvati |
| Qualcomm AVB2 via GPT PoC | Nema potvrđenog uslova dinamičke selekcije na Honor firmware-u, nema potvrđenog write pristupa i boot environment-a |
| GhostLock kineski Honor 70 kernel | Binarnom profilu ne odgovara FNE-NX9 kernel hash; privremeni root nije dokaz bootloader otključavanja |
| EDL/QFIL/servisni loader | Model podržan od strane nekih profesionalnih servisnih alata, ali to **nije isto** što i podržan unlock ili garantovan GPT write/restore |
| Unsigned EFI u `efisp` | U stock GPT ne postoji imenovana particija `efisp` |

## Bezbedna odluka za ovaj uređaj

**Ne izvoditi trenutno nikakve upise** u `frp`, `oeminfo`, `devinfo`, `vbmeta`, GPT, `abl`, `xbl` ili RPMB. Ne raditi test-point kratkospojeve, EDL write, fusible exploit komande ili promenu boot chain-a radi nagađanja. Ako neki servisni alat tvrdi da podržava trajno otključavanje upravo FNE-NX9 C431 MagicOS 8.0.290, potrebno je prvo pribaviti konkretan validiran postupak, kompatibilan loader i metod kompletne obnove, inače rizik nije opravdan.

**Ostaju nepoznanice:** vrednost aktivnog Keymaster fuse-a u trenutku pokušaja, trenutno učitani FRP disk flag, stvarna implementacija/politika aktivnog Fastboot handlera, način izbora AVB2 u Honor-ovom ABL-u, i dostupnost autorizovane EDL operacije za otključavanje na baš ovoj verziji.

## Originalni artefakti i dokazni logovi

- [System OEMLock / FRP](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42537052942)
- [XBL `VerifiedBootDxe` dekompajliranje](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42538078141)
- [KM41 dispečer i milestone](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42540051134)
- [KM41 stvarni READ/WRITE milestone guard](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42540518094)
- [KM41 alias ID provera iz originalnih ELF bajtova](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42540815245)
- [Originalni ABL ARM64 milestone callsite](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42541488610)
- [UTF-16LE `vbmeta` / GPT xrefs originalnog ABL-a](https://github.com/PetarM09/honor70-firmware-analysis/actions/runs/42541876678)
- [Javni Qualcomm AVB exploit — drugi uređaj, **nije potvrđen Honor 70**](https://github.com/atlas4381/qualcomm_avb_exploit_poc)
