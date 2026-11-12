#!/usr/bin/env python3
"""Fail-closed C431 v0.6 evidence coherence against v0.5 and selected FDT report."""
import argparse,json
from pathlib import Path
EXPECTED_BASE="bc692b769082c3db077864b82b6410b0d8ca93c0ce6985f9a5adedfb8b9854e9"
EXPECTED_OVERLAY="c278a52783cc0c4093f79772dd9f1036d38135098deb56159150da3f82c985cc"
COUNTS={"base_exported_symbols_count":1574,
        "external_fixup_labels_resolved":165,
        "external_fixup_patch_sites_valid":468,
        "overlay_fragment_targets_resolved":137,
        "overlay_fragments_total":137,
        "local_fixup_nodes":207,
        "local_fixup_patch_sites_valid":262,
        "fragments_targeting_memory":0,
        "fragments_targeting_reserved_memory":1}
def verify(old,new,report):
    if old.get("profile_version")!="0.5.0" or new.get("profile_version")!="0.6.0":
        raise ValueError("Expected v0.5 and v0.6")
    for name in ("target","provenance","confirmed_binary_offsets_bytes",
                 "unresolved_required_fields","confirmed_stack_evidence",
                 "compiled_kernel_config","confirmed_compiled_oem_config",
                 "on_device_boot_tree_selection","uploaded_vendor_boot_dtbo_evidence"):
        if old.get(name)!=new.get(name):
            raise ValueError("Unjustified profile provenance/layout change "+name)
    missing=new["unresolved_required_fields"]
    if len(missing)!=10 or any(v is not None for v in missing.values()):
        raise ValueError("Unknown runtime offsets must stay unknown")
    flags=new.get("checks",{})
    for name in ("exploit_loader_enabled","active_uaf_trigger_enabled",
                 "kernel_memory_write_enabled","root_installation_enabled",
                 "persistent_unlock_enabled","run_ready_ghostlock_profile",
                 "actual_kernel_phys_load_from_fdt","actual_merged_fdt_verified"):
        if flags.get(name) is not False:
            raise ValueError("Unsafe live claim "+name)
    e=new.get("selected_fdt_overlay_fixup_audit",{})
    hashes=e.get("verified_source",{})
    if hashes.get("base_fdt_sha256")!=EXPECTED_BASE or hashes.get("selected_overlay_sha256")!=EXPECTED_OVERLAY:
        raise ValueError("Wrong selected FDT digest")
    if (report.get("base_dtb",{}).get("sha256")!=EXPECTED_BASE or
        report.get("selected_overlay",{}).get("sha256")!=EXPECTED_OVERLAY):
        raise ValueError("Wrong source report FDT digests")
    if report.get("selected_overlay",{}).get("board_id_decimal")!=8790:
        raise ValueError("Original FNE-NX9 board-id missing")
    source=report.get("external_fixups",{})
    fragments=report.get("fragments",{})
    local=report.get("internal_fixups",{})
    observed={
        "base_exported_symbols_count":source.get("base_exported_symbols"),
        "external_fixup_labels_resolved":source.get("external_symbols_resolved"),
        "external_fixup_patch_sites_valid":source.get("patch_sites_valid"),
        "overlay_fragment_targets_resolved":fragments.get("targets_resolved"),
        "overlay_fragments_total":fragments.get("total"),
        "local_fixup_nodes":local.get("local_fixup_nodes"),
        "local_fixup_patch_sites_valid":local.get("patch_sites_valid"),
        "fragments_targeting_memory":fragments.get("targeting_memory"),
        "fragments_targeting_reserved_memory":fragments.get("targeting_reserved_memory")}
    for key,value in COUNTS.items():
        if observed.get(key)!=value or e.get(key)!=value:
            raise ValueError("Evidence mismatch "+key)
    reserved=e.get("reserved_memory_overlay",{})
    memory=report.get("memory_evidence",{})
    if reserved.get("reg_identical_to_base") is not True or memory.get("removed_region_reg_unchanged") is not True:
        raise ValueError("Unverified reserved-memory claim")
    if reserved.get("no_map_identical_to_base") is not True or memory.get("removed_region_no_map_unchanged") is not True:
        raise ValueError("Unverified no-map claim")
    if e.get("base_hyp_reserved")!=memory.get("base_hyp_reserved") or e.get("base_memory_reg")!=memory.get("base_memory_reg"):
        raise ValueError("Observed original RAM placeholder differs")
    if any(e.get(k) is not False for k in (
        "full_fdtoverlay_merge_applied_and_validated",
        "actual_live_merged_fdt_attested",
        "signed_device_partition_byte_attested",
        "kernel_phys_load_derived_from_source",
        "runtime_slide_known")):
        raise ValueError("Live FDT or kernel address was not observed")
    return {"schema_version":1,"profile_version":"0.6.0",
            "verified_original_base_sha256":EXPECTED_BASE,
            "verified_original_overlay_sha256":EXPECTED_OVERLAY,
            "confirmed_C431_struct_offsets":len(new["confirmed_binary_offsets_bytes"]),
            "original_overlay_fragment_targets":COUNTS["overlay_fragments_total"],
            "external_symbol_labels":COUNTS["external_fixup_labels_resolved"],
            "external_relocation_patch_sites":COUNTS["external_fixup_patch_sites_valid"],
            "local_relocation_patch_sites":COUNTS["local_fixup_patch_sites_valid"],
            "unresolved_kernel_ghostlock_fields":len(missing),
            "live_merged_fdt_proven":False,"kernel_phys_load_proven":False,
            "uaf_or_root_proven":False,"device_operations":0,
            "status":"signed-source-hash-matched_selected_overlay_fixup_structure_only"}
if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ("old","new","report","out"):
        parser.add_argument("--"+key,type=Path,required=True)
    args=parser.parse_args()
    inputs=[json.loads(getattr(args,k).read_text()) for k in ("old","new","report")]
    result=verify(*inputs)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
