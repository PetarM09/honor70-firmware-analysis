#!/usr/bin/env python3
"""Fail-closed matching of boot-reported C431 FDT indices with saved image evidence.

This compares *reported* Android ro.boot properties with the observed uploaded
partition's indexed FDT structures. It never claims a live merged DT, kernel
physical address, KASLR bypass, UAF, exploit or root.
"""
import argparse,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
EXPECTED_BASE="bc692b769082c3db077864b82b6410b0d8ca93c0ce6985f9a5adedfb8b9854e9"
EXPECTED_OVERLAY="c278a52783cc0c4093f79772dd9f1036d38135098deb56159150da3f82c985cc"

def verify(old,new,observed,source):
    if old.get("profile_version")!="0.4.0" or new.get("profile_version")!="0.5.0":
        raise ValueError("Unexpected profile version")
    for key in ("target","provenance","confirmed_binary_offsets_bytes",
                "confirmed_stack_evidence","compiled_kernel_config",
                "unresolved_required_fields","confirmed_compiled_oem_config"):
        if old.get(key)!=new.get(key): raise ValueError("Original C431 field changed: "+key)
    if any(val is not None for val in new["unresolved_required_fields"].values()):
        raise ValueError("Unproven runtime fields populated")
    if len(new["unresolved_required_fields"])!=10: raise ValueError("Wrong number of unresolved fields")
    for key in ("exploit_loader_enabled","active_uaf_trigger_enabled",
                "kernel_memory_write_enabled","root_installation_enabled",
                "persistent_unlock_enabled","run_ready_ghostlock_profile"):
        if new.get("checks",{}).get(key) is not False:
            raise ValueError("Unsafe execution state: "+key)
    boot=observed.get("phone_reported_properties",{})
    if boot.get("ro.boot.dtb_idx")!="13" or boot.get("ro.boot.dtbo_idx")!="18":
        raise ValueError("Observed phone index changed")
    selection=new.get("on_device_boot_tree_selection",{})
    if (selection.get("bootloader_reported_base_dtb_index"),
        selection.get("bootloader_reported_dtbo_index"))!=(13,18):
        raise ValueError("Expected live getprop indices missing")
    if selection.get("reported_hardware_version")!=boot.get("ro.board.hardware_version"):
        raise ValueError("Hardware revision not tied to observed property")
    if selection.get("reported_boardid")!=boot.get("ro.board.boardid"):
        raise ValueError("Board ID not tied to observed property")
    uploaded=source.get("source_files",{})
    ref=new.get("uploaded_vendor_boot_dtbo_evidence",{})
    if (uploaded.get("vendor_boot_a_img",{}).get("sha256") !=
        ref.get("vendor_boot_partition",{}).get("image_sha256") or
        uploaded.get("dtbo_a_img",{}).get("sha256") !=
        ref.get("dtbo_partition",{}).get("image_sha256")):
        raise ValueError("Wrong uploaded original images")
    selected=source.get("selected_fdt_entries",{})
    base=selected.get("base_dtb_13",{})
    overlay=selected.get("overlay_dtbo_18",{})
    other=selected.get("overlay_dtbo_25",{})
    b=selection.get("selected_base_dtb_from_uploaded_vendor_boot",{})
    o=selection.get("selected_overlay_from_uploaded_dtbo",{})
    if (base.get("index")!=13 or
        base.get("sha256")!=EXPECTED_BASE or
        base.get("sha256")!=b.get("sha256") or
        base.get("model")!=[b.get("model")]):
        raise ValueError("Boot-reported base FDT #13 mismatch")
    if (overlay.get("index")!=18 or
        overlay.get("sha256")!=EXPECTED_OVERLAY or
        overlay.get("sha256")!=o.get("sha256") or
        overlay.get("model")!=[o.get("model")]):
        raise ValueError("Boot-reported DTBO #18 mismatch")
    if (overlay.get("qcom_board_id_decimal")!=8790 or
        overlay.get("qcom_board_id_hex")!="0x2256" or
        o.get("qcom_board_id_decimal")!=8790 or
        o.get("qcom_board_id_hex")!="0x2256" or
        boot.get("ro.board.boardid")!="8790"):
        raise ValueError("Independent QCOM board-id #18 mismatch")
    if (overlay.get("hardware_version")!=boot.get("ro.board.hardware_version") or
        o.get("hardware_version")!=boot.get("ro.board.hardware_version") or
        overlay.get("board_name")!=o.get("board_name")):
        raise ValueError("Independent reported board hardware variant mismatch")
    if (other.get("qcom_board_id_decimal")!=8780 or
        other.get("qcom_board_id_hex")!="0x224c" or
        o.get("alternative_index_25_board_id_decimal")!=8780):
        raise ValueError("Alternative DTBO #25 board-id not distinguished")
    if selection.get("board_id_matches_dtbo_18") is not True or (
        selection.get("board_id_mismatches_dtbo_25") is not True):
        raise ValueError("Phone board-ID corroboration not retained")
    if other.get("sha256")==EXPECTED_OVERLAY:
        raise ValueError("Alternative FNE-NX9 #25 surprisingly identical")
    if (other.get("index")!=25 or
        other.get("model")!=overlay.get("model") or
        selection.get("selected_overlay_from_uploaded_dtbo",{}).get(
            "alternate_same_model_table_index_not_selected")!=25):
        raise ValueError("Alternative model and index not audited")
    if selection.get("actual_active_merged_fdt_directly_read") is not False or (
        selection.get("uploaded_partition_sha_verified_against_live_partitions") is not False):
        raise ValueError("Do not falsely claim live DTB verified")
    return {
        "schema_version":1,
        "profile_id":new["profile_id"],
        "profile_version":new["profile_version"],
        "ro_boot_dtb_idx_reported":13,
        "ro_boot_dtbo_idx_reported":18,
        "matching_base_fdt_model":b["model"],
        "matching_base_fdt_sha256":b["sha256"],
        "matching_overlay_model":o["model"],
        "matching_overlay_sha256":o["sha256"],
        "alternative_same_model_index":25,
        "board_hardware_version":selection["reported_hardware_version"],
        "phone_boardid_decimal":8790,
        "matching_overlay_boardid_hex":"0x2256",
        "same_model_alternative_boardid_hex":"0x224c",
        "same_model_alternative_boardid_decimal":8780,
        "genuinely_selected_merged_fdt_attested":False,
        "live_partition_byte_identity_attested":False,
        "kernel_phys_load_confirmed":False,
        "unresolved_profile_field_count":10,
        "runtime_uaf_or_root_attempted":False,
        "device_operations":0,
        "status":"phone_reported_fdt_index_to_uploaded_image_correspondence_confirmed"
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--old",type=Path,default=ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile-v0.4.json")
    p.add_argument("--new",type=Path,default=ROOT/"profiles/fne-nx9-c431-8.0.0.290.profile-v0.5.json")
    p.add_argument("--observed",type=Path,default=ROOT/"profiles/evidence/fne-nx9-c431-phone-boot-dtb13-dtbo18-2026-11-12.json")
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    inputs=[json.loads(getattr(a,key).read_text()) for key in ("old","new","observed","source")]
    result=verify(*inputs)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
if __name__=="__main__":
    main()
