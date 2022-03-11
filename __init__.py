#!/usr/bin/env python3
# All that is required is to provide functions similar to "is_valid" and "parse_info" below, and call
# `binaryninja.debuginfo.DebugInfoParser.register` with a name for your parser; your parser will be made
# available for all valid binary views, with the ability to parse and apply debug info to existing BNDBs.
import binaryninja as bn
from elftools import dwarf
from elftools.elf import elffile


def record_function(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, func_die: dwarf.die):
    bn.log_debug(f"Recording function: {func_die.attributes['DW_AT_name'].value} at addr {hex(func_die.attributes['DW_AT_low_pc'].value)}")
    function_info = bn.debuginfo.DebugFunctionInfo(
        full_name=func_die.attributes["DW_AT_name"].value, address=func_die.attributes["DW_AT_low_pc"].value,
    )
    debug_info.add_function(function_info)


def record_type(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, dwarf_info: dwarf.dwarfinfo):
    return None


def record_struct(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, dwarf_info: dwarf.dwarfinfo):
    return None


def is_valid(bv: bn.binaryview.BinaryView):
    if bv.view_type != "ELF":
        return False

    file_obj = open(bv.file.filename, 'rb')
    elf_file = elffile.ELFFile(file_obj)
    return elf_file.has_dwarf_info()


def parse_info(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView):
    file_obj = open(bv.file.filename, 'rb')
    elf_file = elffile.ELFFile(file_obj)
    dwarf_info = elf_file.get_dwarf_info()

    for CU in dwarf_info.iter_CUs():
        for DIE in CU.get_top_DIE().iter_children():
            if DIE.tag == "DW_TAG_subprogram":
                record_function(debug_info, bv, DIE)

    file_obj.close()
    """
    debug_info.add_type("name", bn.types.Type.int(4, True))
    debug_info.add_data_variable(0x1234, bn.types.Type.int(4, True), "name")
    debug_info.add_data_variable(0x4321, bn.types.Type.int(4, True))  # Names are optional
    function_info = bn.debuginfo.DebugFunctionInfo("short_name", "full_name", "raw_name", 0xdead1337,
                                                   bn.types.Type.int(4, False), [])
    debug_info.add_function(function_info)"""


bn.debuginfo.DebugInfoParser.register("dwarf-debug-parser", is_valid, parse_info)
