#!/usr/bin/env python3
"""Cross-check original signed HONOR70 Fastboot RX allocation and parser bounds.

Proves the hypothesized 64-byte off-by-one does NOT occur on the normal USB
receive path: the original firmware allocates a much larger buffer. This is
not a whole-program memory safety assessment and sends no device commands.
"""
import argparse,hashlib,json,re
from pathlib import Path

def body(src,marker):
    i=src.find(marker)
    if i<0:raise ValueError("Missing signed firmware function "+marker)
    next_marker=re.search(r"(?m)^===== (?:RX_INIT_TARGET|BOUNDS_TARGET) ",src[i+len(marker):])
    end=i+len(marker)+next_marker.start() if next_marker else len(src)
    return src[i:end]

def need(s,token,label):
    if token not in s:raise ValueError("Missing original code condition "+label)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--parser-ghidra",required=True,type=Path)
    p.add_argument("--rxinit-ghidra",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    raw_parser=a.parser_ghidra.read_bytes()
    raw_rx=a.rxinit_ghidra.read_bytes()
    parser=raw_parser.decode("utf8","replace")
    rx=raw_rx.decode("utf8","replace")
    fparse=body(parser,"===== BOUNDS_TARGET 00022c7c =====")
    falloc=body(rx,"===== RX_INIT_TARGET 000205d0 =====")
    frecv=body(rx,"===== RX_INIT_TARGET 00020328 =====")
    fcallback=body(parser,"===== BOUNDS_TARGET 00022a64 =====")
    need(falloc,"(0x1000000,&DAT_001c1738)","RX heap allocation 16MiB")
    need(frecv,"(1,0x1ff,DAT_001c1738)","USB 511 byte read into RX buffer")
    need(frecv,"FUN_00022a64(uVar6,uVar5)","USB receive event to original Fastboot callback")
    need(fcallback,"FUN_00022c7c()","normal receive command callback to parser")
    need(fparse,"if (0x3f < uVar9)","Fastboot command clamp")
    need(fparse,"uVar9 = 0x40;","max command terminator index 64")
    need(fparse,"*(undefined1 *)(auVar13._8_8_ + uVar9) = 0;","NUL written at clamped index")
    need(fparse,"FUN_000134c0(auVar13._8_8_)","locked command gate after NUL")
    observed={
        "normal_usb_rx_allocated_bytes":0x1000000,
        "normal_receive_request_bytes":0x1ff,
        "fastboot_cmd_nul_max_index":0x40,
        "normal_usb_rx_0x40_nul_within_allocated_bounds":True,
        "source_parser_ghidra_sha256":hashlib.sha256(raw_parser).hexdigest(),
        "source_rxinit_ghidra_sha256":hashlib.sha256(raw_rx).hexdigest(),
        "chain":[
            "0x205D0 allocates 0x1000000 bytes via USB protocol to DAT_001C1738",
            "0x20328 receives up to 0x1FF bytes into DAT_001C1738",
            "USB callback 0x22A64 calls generic parser 0x22C7C",
            "0x22C7C writes a terminator at a maximum of index 0x40",
            "0x22C7C later invokes locked-mode gate 0x134C0"
        ],
        "limitations":[
            "Normal USB receive path proof, not an audit of every possible caller or corruption.",
            "Ghidra indirect UEFI protocol signatures are recovered heuristically; the allocation size is an exact original code constant.",
            "No CVE attribution or arbitrary code execution demonstrated.",
            "No permanent bootloader unlock method demonstrated.",
            "No malformed Fastboot commands, EDL writes or live device actions performed."
        ]
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(observed,indent=2)+"\n")
    print("NORMAL_USB_PRE_GATE_64_BYTE_OOB_HYPOTHESIS_REJECTED")
    print(json.dumps(observed,sort_keys=True))

if __name__=="__main__":main()
