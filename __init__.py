#!/usr/bin/env python3
from typing import Optional

import binaryninja as bn
from elftools import dwarf
from elftools.dwarf import descriptions
from elftools.elf import elffile

from .utils import get_attribute_str_value


def get_pointer_type(data_type_die: dwarf.die, bv: bn.binaryview.BinaryView, pointer_level: int = 1) -> Optional[tuple]:
    # Check for void pointer
    if "DW_AT_type" not in data_type_die.attributes:
        return bv.parse_type_string("void" + "*" * pointer_level)

    child_type_die = data_type_die.get_DIE_from_attribute("DW_AT_type")
    if child_type_die.tag == "DW_TAG_pointer_type":
        return get_pointer_type(child_type_die, bv, pointer_level + 1)

    elif child_type_die.tag == "DW_TAG_typedef":
        new_type_str = get_attribute_str_value(data_type_die, "DW_AT_name")
        new_type_str += "*" * pointer_level
        bv_type = recover_data_type(bv, child_type_die)
        if bv_type is None:

            return None
        else:
            return new_type_str, bv_type

    elif child_type_die.tag == "DW_TAG_base_type":
        new_type_str = get_attribute_str_value(child_type_die, "DW_AT_name")
        new_type_str += "*" * pointer_level
        return new_type_str, recover_data_type(bv, child_type_die)

    else:
        bn.log_error(f"Unknown child_type TAG in get_pointer_type: {child_type_die.tag}")
        return None


# Recover Data Type and return a tuple to the calling function for further construction or recording
def recover_data_type(bv: bn.binaryview.BinaryView, data_type_die: dwarf.die) -> Optional[tuple[str, bn.types.Type]]:
    if data_type_die.tag == "DW_TAG_structure_type" and ('DW_AT_name' not in data_type_die.attributes):
        # This is a typedef-ed structure. A DW_TAG_typedef DIE will record this struct later
        return
    if data_type_die.tag == "DW_TAG_pointer_type":
        # pointer_type DIEs don't have a name attribute
        pointer_type = get_pointer_type(data_type_die, bv)
        if pointer_type is None:
            return

    elif data_type_die.tag == "DW_TAG_array_type":
        return
    elif data_type_die.tag == "DW_TAG_structure_type":
        return
        # change func to attempt to create struct return None if failed
        # due to unknown type
    elif data_type_die.tag == "DW_TAG_typedef":
        return
    else:
        bn.log_error(f"Encountered unknown TAG in record_data_type() - {data_type_die.tag}")
    return None


def record_function(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, func_die: dwarf.die) -> bool:
    # Grab return type
    ret_type = None
    if "DW_AT_type" not in func_die.attributes:
        ret_type = bn.types.Type.void()
    else:
        type_die = func_die.get_DIE_from_attribute("DW_AT_type")
        ret_type = bv.parse_type_string(get_attribute_str_value(type_die, "DW_AT_name"))[0]

    function_info = bn.debuginfo.DebugFunctionInfo(
        full_name=get_attribute_str_value(func_die, 'DW_AT_name'), address=func_die.attributes["DW_AT_low_pc"].value,
        return_type=ret_type
    )
    return debug_info.add_function(function_info)


def recover_data_variable(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, variable_die: dwarf.die,
                          cu: dwarf.compileunit.CompileUnit) -> bool:
    # Get name of data var
    name = get_attribute_str_value(variable_die, "DW_AT_name")
    bn.log_debug(f"Examining data var - name: {name}")

    # Get type of data var
    data_type_die = variable_die.get_DIE_from_attribute("DW_AT_type")
    data_type_tuple = recover_data_type(bv, data_type_die)
    debug_info.add_type(data_type_tuple[0], data_type_tuple[1])

    # Get location of data var in memory
    expr_dump_obj = dwarf.descriptions.ExprDumper(cu.structs)
    location_str = expr_dump_obj.dump_expr(variable_die.attributes['DW_AT_location'].value, cu.cu_offset)
    address_str = location_str.split(' ', 1)[1]
    address = int(address_str, 16)

    bn.log_debug(f"Creating data var: {name} @ {hex(address)} with type: {data_type_tuple[0]}")
    return debug_info.add_data_variable(address, data_type_tuple[1], name)


def is_valid(bv: bn.binaryview.BinaryView) -> bool:
    if bv.view_type != "ELF":
        return False

    file_obj = open(bv.file.filename, 'rb')
    elf_file = elffile.ELFFile(file_obj)
    return elf_file.has_dwarf_info()


def parse_info(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView) -> None:
    file_obj = open(bv.file.filename, 'rb')
    elf_file = elffile.ELFFile(file_obj)
    dwarf_info = elf_file.get_dwarf_info()
    # Data type recovery will be done as needed when recovering data_variables and functions

    # iter CUs for functions
    for CU in dwarf_info.iter_CUs():
        for DIE in CU.get_top_DIE().iter_children():
            if DIE.tag == "DW_TAG_subprogram":
                record_function(debug_info, bv, DIE)

    # iter CUs for data_variables
    for CU in dwarf_info.iter_CUs():
        for DIE in CU.get_top_DIE().iter_children():
            if DIE.tag == "DW_TAG_variable":
                recover_data_variable(debug_info, bv, DIE, CU)

    file_obj.close()


bn.debuginfo.DebugInfoParser.register("dwarf-debug-parser", is_valid, parse_info)
