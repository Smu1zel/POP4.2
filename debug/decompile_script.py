import ida_hexrays
import ida_funcs
import idc
import ida_auto
import os
import traceback

print("IDAPython script started...")
ida_auto.auto_wait()
print("Auto-analysis complete.")

def dump_assembly(func_name, output_file):
    print(f"Dumping assembly for {func_name}...")
    addr = idc.get_name_ea_simple(func_name)
    if addr == idc.BADADDR:
        print(f"Assembly dump: function {func_name} not found.")
        return False
        
    func = ida_funcs.get_func(addr)
    if not func:
        print(f"Assembly dump: could not get function for {func_name}")
        return False
        
    start = func.start_ea
    end = func.end_ea
    
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"; ==========================================\n")
        f.write(f"; Assembly: {func_name} at 0x{start:X} - 0x{end:X}\n")
        f.write(f"; ==========================================\n")
        
        curr = start
        while curr < end:
            disasm = idc.generate_disasm_line(curr, 0)
            f.write(f"0x{curr:X}:  {disasm}\n")
            curr = idc.next_head(curr, end)
            
    print(f"Successfully dumped assembly for {func_name} to {output_file}")
    return True

def decompile_func(func_name, output_file):
    print(f"Decompiling {func_name}...")
    addr = idc.get_name_ea_simple(func_name)
    if addr == idc.BADADDR:
        print(f"Decompile: function {func_name} not found.")
        return False
        
    func = ida_funcs.get_func(addr)
    if not func:
        return False
        
    try:
        cfunc = ida_hexrays.decompile(func)
        if cfunc:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"// ==========================================\n")
                f.write(f"// Function: {func_name} at 0x{addr:X}\n")
                f.write(f"// ==========================================\n")
                f.write(str(cfunc))
                f.write("\n\n")
            print(f"Successfully decompiled {func_name}")
            return True
        else:
            print(f"Decompilation of {func_name} returned empty cfunc.")
    except Exception as e:
        print(f"Failed to decompile {func_name}: {e}")
        traceback.print_exc()
    return False

c_output = os.path.abspath("decompiled.c")
asm_output = os.path.abspath("assembly.asm")

with open(c_output, "w", encoding="utf-8") as f:
    f.write("// Decompiled with IDAPython\n\n")

with open(asm_output, "w", encoding="utf-8") as f:
    f.write("; Assembly Dump with IDAPython\n\n")

# Try to initialize decompiler
decompiler_ok = ida_hexrays.init_hexrays_plugin()
if decompiler_ok:
    print("Hex-Rays plugin initialized.")
else:
    print("Hex-Rays plugin not available.")

functions_to_dump = [
    "KiSystemStartup",
    "KiInitializeBootStructures",
    "KiInitializeKernel",
    "KiInitSystem",
    "KiSetFeatureBits",
    "KiInitializeProcessor"
]

for name in functions_to_dump:
    if decompiler_ok:
        decompile_func(name, c_output)
    dump_assembly(name, asm_output)

print("Exiting IDA...")
idc.qexit(0)
