"""No-device synthetic binary-FDT regression suite for C431 DTB13/DTBO18."""
import hashlib,struct,unittest
from audit_fne_c431_selected_fdt_overlay import parse,verify

def fdt(nodes):
    names=sorted({k for props in nodes.values() for k in props})
    names_off={};string_bytes=bytearray()
    for name in names:
        names_off[name]=len(string_bytes)
        string_bytes+=name.encode()+b'\0'
    data=bytearray();stack=[]
    def begin(name):
        data.extend(struct.pack(">I",1)+name.encode()+b'\0')
        data.extend(b'\0'*(-len(data)%4))
    for path,props in nodes.items():
        pieces=[] if path=="/" else path.lstrip("/").split("/")
        common=0
        for a,b in zip(pieces,stack):
            if a!=b:break
            common+=1
        for _ in stack[common:]:data.extend(struct.pack(">I",2))
        stack=stack[:common]
        for part in pieces[common:]:
            begin(part)
            stack.append(part)
        for key,value in props.items():
            data.extend(struct.pack(">III",3,len(value),names_off[key]))
            data.extend(value)
            data.extend(b'\0'*(-len(data)%4))
    for _ in stack:data.extend(struct.pack(">I",2))
    # Wrap all nodes in an explicit root BEGIN/END pair
    inner=struct.pack(">I",1)+b'\0'*4+data+struct.pack(">II",2,9)
    struct_off=56
    string_off=struct_off+len(inner)
    header=struct.pack(">10I",0xd00dfeed,string_off+len(string_bytes),
        struct_off,string_off,40,17,16,0,len(string_bytes),len(inner))
    return header+b'\0'*16+inner+string_bytes

def sample():
    base={
        "/":{"model":b"Qualcomm Technologies, Inc. Yupik SoC\0"},
        "/reserved-memory":{},
        "/reserved-memory/hyp@80000000":{"reg":struct.pack(">QQ",0x80000000,0x600000)},
        "/reserved-memory/removed_region@c0000000":{
            "reg":struct.pack(">QQ",0xc0000000,0x5500000),"no-map":b""},
        "/soc":{},
        "/memory":{"reg":struct.pack(">QQ",0,0)},
        "/__symbols__":{"reserved_memory":b"/reserved-memory\0"}}
    over={
        "/":{"model":b"Honor Technologies, Inc. FNE-NX9-781-208\0",
             "qcom,board-id":struct.pack(">II",8790,0)},
        "/fragment@0":{"target":b"\xff"*4},
        "/fragment@0/__overlay__":{"sample":struct.pack(">I",1)},
        "/fragment@0/__overlay__/removed_region@c0000000":{
            "reg":struct.pack(">QQ",0xc0000000,0x5500000),"no-map":b""},
        "/__fixups__":{"reserved_memory":b"/fragment@0:target:0\0"},
        "/__local_fixups__":{},
        "/__local_fixups__/fragment@0":{},
        "/__local_fixups__/fragment@0/__overlay__":{
            "sample":struct.pack(">I",0)}}
    return base,over

def run(base,overlay):
    b=fdt(base);o=fdt(overlay)
    return verify(b,o,expected_base=hashlib.sha256(b).hexdigest(),
                       expected_overlay=hashlib.sha256(o).hexdigest())

class Tests(unittest.TestCase):
    def test_valid_synthetic_fdt(self):
        a,b=sample();r=run(a,b)
        self.assertEqual(r["fragments"]["targets_resolved"],1)
        self.assertEqual(r["external_fixups"]["patch_sites_valid"],1)
        self.assertEqual(r["internal_fixups"]["patch_sites_valid"],1)
        self.assertTrue(r["memory_evidence"]["removed_region_reg_unchanged"])
        self.assertFalse(r["kernel_phys_load_known"])
    def test_magic_rejected(self):
        a,b=sample();data=fdt(a)
        with self.assertRaises(ValueError):parse(b"BAD!"+data[4:])
    def test_wrong_sha_rejected(self):
        a,b=sample();data=fdt(a);ov=fdt(b)
        with self.assertRaises(ValueError):
            verify(data,ov,expected_base="0"*64,expected_overlay=hashlib.sha256(ov).hexdigest())
    def test_unknown_symbol_rejected(self):
        a,b=sample()
        b["/__fixups__"]={"not_present":b"/fragment@0:target:0\0"}
        with self.assertRaises(ValueError):run(a,b)
    def test_bad_external_offset_rejected(self):
        a,b=sample()
        b["/__fixups__"]={"reserved_memory":b"/fragment@0:target:8\0"}
        with self.assertRaises(ValueError):run(a,b)
    def test_unmapped_fragment_rejected(self):
        a,b=sample()
        b["/fragment@1"]={"target":b"\xff"*4}
        b["/fragment@1/__overlay__"]={}
        with self.assertRaises(ValueError):run(a,b)
    def test_bad_local_fixup_rejected(self):
        a,b=sample()
        b["/__local_fixups__/fragment@0/__overlay__"]["sample"]=struct.pack(">I",4)
        with self.assertRaises(ValueError):run(a,b)
    def test_absent_base_target_rejected(self):
        a,b=sample()
        a["/__symbols__"]["reserved_memory"]=b"/does-not-exist\0"
        with self.assertRaises(ValueError):run(a,b)
    def test_already_patched_fragment_rejected(self):
        a,b=sample()
        b["/fragment@0"]["target"]=struct.pack(">I",0x55)
        with self.assertRaises(ValueError):run(a,b)
    def test_declared_ram_not_runtime_kernel_load(self):
        a,b=sample();r=run(a,b)
        self.assertEqual(r["memory_evidence"]["base_memory_reg"],[{"start":"0x0","size":"0x0"}])
        self.assertFalse(r["active_merged_fdt_read"])
        self.assertFalse(r["ghostlock_uaf_or_root_tested"])

if __name__=="__main__":unittest.main()
