#!/usr/bin/env python3
# All that is required is to provide functions similar to "is_valid" and "parse_info" below, and call
# `binaryninja.debuginfo.DebugInfoParser.register` with a name for your parser; your parser will be made
# available for all valid binary views, with the ability to parse and apply debug info to existing BNDBs.
import binaryninja as bn
from elftools.elf.elffile import ELFFile


def is_valid(bv: bn.binaryview.BinaryView):
    if bv.view_type != "Raw":
        return False

    file_obj = open(bv.file.filename, 'rb')
    elf_file = ELFFile(file_obj)
    return elf_file.has_dwarf_info()


def parse_info(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView):
    file_obj = open(bv.file.filename, 'rb')
    elf_file = ELFFile(file_obj)
    """debug_info.add_type("name", bn.types.Type.int(4, True))

    debug_info.add_data_variable(0x1234, bn.types.Type.int(4, True), "name")
    debug_info.add_data_variable(0x4321, bn.types.Type.int(4, True))  # Names are optional
    # Just provide the information you can; we can't create the function without an address, but we'll
    # figure out what we can and you can query this info later when you have a better idea of things
    function_info = bn.debuginfo.DebugFunctionInfo("short_name", "full_name", "raw_name", 0xdead1337,
                                                   bn.types.Type.int(4, False), [])
    debug_info.add_function(function_info)"""


bn.debuginfo.DebugInfoParser.register("dwarf-debug-parser", is_valid, parse_info)
