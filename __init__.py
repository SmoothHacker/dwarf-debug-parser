#!/usr/bin/env python3
# All that is required is to provide functions similar to "is_valid" and "parse_info" below, and call
# `binaryninja.debuginfo.DebugInfoParser.register` with a name for your parser; your parser will be made
# available for all valid binary views, with the ability to parse and apply debug info to existing BNDBs.
from typing import Optional
from collections import deque

from pprint import pp

import binaryninja as bn
from binaryninja import Type
from elftools import dwarf
from elftools.dwarf import descriptions
from elftools.elf import elffile

# Append DIEs for DW_TAG_pointer_types that need to be visited at the end of the type parsing process
unknown_type_DIEs = deque([])


# If return type is none then the DIE should be added to unknown_type_DIEs
def check_if_type_exists(type_str: str, bv: bn.binaryview.BinaryView) -> Optional[Type]:
    try:
        return bv.parse_type_string(type_str)[0]  # Gets bn.types.Type from tuple
    except SyntaxError:
        # Type is unknown to the current binary view
        return None


def get_pointer_type(data_type_die: dwarf.die, bv: bn.binaryview.BinaryView, pointer_level: int) -> Optional[Type]:
    child_type = data_type_die.get_DIE_from_attribute("DW_AT_type")
    if child_type.tag == "DW_TAG_pointer_type":
        return get_pointer_type(child_type, bv, pointer_level + 1)

    elif child_type.tag == "DW_TAG_typedef":
        new_type_str = get_attribute_str_value(data_type_die, "DW_AT_name")
        new_type_str += "*" * pointer_level
        return check_if_type_exists(new_type_str, bv)

    elif child_type.tag == "DW_TAG_base_type":
        new_type_str = get_attribute_str_value(data_type_die, "DW_AT_name")
        new_type_str += "*" * pointer_level
        return bv.parse_type_string(new_type_str)[0]

    else:
        bn.log_error(f"Unknown child_type TAG in get_pointer_type: {child_type.tag}")
        return None


# If all the types of the struct are recognized by the binary_view then return true.
# If not then return false
def check_struct_types(data_type_die: dwarf.die, bv: bn.binaryview.BinaryView) -> bool:
    for child in data_type_die.iter_children():
        member_type_die = child.get_DIE_from_attribute("DW_AT_type")
        if member_type_die.tag == "DW_base_type":
            # bv is guaranteed to recognize a base type
            continue
        elif member_type_die.tag == "DW_TAG_pointer_type":
            # Calls recursive func to follow pointers
            bv_type = get_pointer_type(data_type_die, bv, 1)
            if bv_type is None:
                unknown_type_DIEs.append(member_type_die)  # add member_type for later processing
                unknown_type_DIEs.append(data_type_die)  # add parent too for later processing
                return False
        elif member_type_die.tag == "DW_TAG_array_type":
            # Found array member
            continue
        else:
            bn.log_error(f"[check_struct_types] Unknown member_type_die TAG: {member_type_die.tag}")
    return True


def get_attribute_str_value(die: dwarf.die, attribute_key: str):
    return die.attributes[attribute_key].value.decode("utf-8")


def record_function(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, func_die: dwarf.die):
    if get_attribute_str_value(func_die, "DW_AT_name") == "local_parameters":
        function_info = bn.debuginfo.DebugFunctionInfo(
            full_name="local_parameters", address=0x4011b0,
            return_type=bn.types.Type.void(), parameters=[("value_1", bn.types.Type.bool()), ("value_2",),
                                                          ("value_3",
                                                           bn.types.Type.pointer(bv.arch, bn.types.Type.char())),
                                                          ("value_4", bn.types.Type.int(1, False)),
                                                          ("value_5", bn.types.Type.char())]
        )
        debug_info.add_function(function_info)

    return
    # Grab return type
    ret_type = None
    if "DW_AT_type" not in func_die.attributes:
        ret_type = bn.types.Type.void()
    else:
        type_die = func_die.get_DIE_from_attribute("DW_AT_type")
        ret_type = bv.parse_type_string(get_attribute_str_value(type_die, "DW_AT_name"))[0]

    # Grab parameter names and types
    param_list = []
    for param_die in func_die.iter_children():
        # Get name
        param_name = get_attribute_str_value(param_die, "DW_AT_name")
        # Get type
        param_type_die = param_die.get_DIE_from_attribute("DW_AT_type")
        param_type = None
        if param_type_die.tag == "DW_AT_pointer_type":
            param_type = bn.types.Type.pointer(bv.arch, bn.types.Type.int(4, False))
        else:
            param_type = bv.parse_type_string(get_attribute_str_value(param_type_die, "DW_AT_name"))[0]

        param_list.append((param_name, param_type))

    pp(param_list)
    function_info = bn.debuginfo.DebugFunctionInfo(
        full_name=get_attribute_str_value(func_die, 'DW_AT_name'), address=func_die.attributes["DW_AT_low_pc"].value,
        return_type=ret_type, parameters=param_list
    )
    debug_info.add_function(function_info)


def record_data_variable(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, variable_die: dwarf.die,
                         cu: dwarf.compileunit.CompileUnit):
    # Get name of data var
    name = get_attribute_str_value(variable_die, "DW_AT_name")
    bn.log_debug(f"Examining data var - name: {name}")

    # Get type of data var
    type_die = variable_die.get_DIE_from_attribute("DW_AT_type")
    data_var_type = None
    if type_die.tag == "DW_TAG_base_type":
        data_var_type_dwarf = get_attribute_str_value(type_die, "DW_AT_name")
        data_var_type = bv.parse_type_string(data_var_type_dwarf)[0]
    elif type_die.tag == "DW_TAG_const_type":
        # Have to come up with better system to parse const composite and primitive types
        return
    elif type_die.tag == "DW_TAG_structure_type":
        return
    else:
        bn.log_error(f"[data_var] Unknown type_die encountered: {type_die.tag}")
        return

    # Get location of data var in memory
    expr_dump_obj = dwarf.descriptions.ExprDumper(cu.structs)
    location_str = expr_dump_obj.dump_expr(variable_die.attributes['DW_AT_location'].value, cu.cu_offset)
    address_str = location_str.split(' ', 1)[1]
    address = int(address_str, 16)

    bn.log_debug(f"Creating data var: {name} @ {hex(address)} with type: {data_var_type.get_string()}")
    debug_info.add_data_variable(address, data_var_type, name)


# Examine data_type_die to see if known to the current binary_view.
# If the type is known then skip the die and return early.
# If the type is not known but its subtypes are known then record the type.
# If the type is not known and any subtype is not also known then queue the data_type_die for later analysis
def record_data_type(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, data_type_die: dwarf.die):
    if data_type_die.tag == "DW_TAG_structure_type" and ('DW_AT_name' not in data_type_die.attributes):
        # This is a typedef-ed structure. A DW_TAG_typedef DIE will record this struct later
        return
    if data_type_die.tag == "DW_TAG_pointer_type":
        # pointer_type DIEs don't have a name attribute
        addr_to_type = data_type_die.attributes['DW_AT_type']
    elif data_type_die.tag == "DW_TAG_array_type":
        return
    else:
        data_type_str = get_attribute_str_value(data_type_die, 'DW_AT_name')
        is_type_known = check_if_type_exists(data_type_str, bv)
        if is_type_known is bn.Type:
            # data_type is known do nothing
            return
        # Data type is not known check if all subtypes are known. If not then queue DIE for later analysis
        # Check if die is a DW_TAG_structure_type
        if data_type_die.tag == "DW_TAG_structure_type":
            check_struct_types(data_type_die, bv)  # change func to attempt to create struct return None if failed
            # due to unknown type
            debug_info.add_type("", None)
        elif data_type_die.tag == "DW_TAG_typedef":
            debug_info.add_type("", None)
        else:
            bn.log_error(f"Encountered unknown TAG in record_data_type() - {data_type_die.tag}")
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

    # iter CUs for types
    for CU in dwarf_info.iter_CUs():
        for DIE in CU.get_top_DIE().iter_children():
            """
            DW_TAG_base_type: a data type that isn't defined in terms of other types
            DW_TAG_typedef: data type that can reference base or composite types. Referred type can be unknown 
                            on first visit.
            """
            if DIE.tag == "DW_TAG_pointer_type" or \
                    DIE.tag == "DW_TAG_array_type" or \
                    DIE.tag == "DW_TAG_typedef" or \
                    DIE.tag == "DW_TAG_structure_type":
                record_data_type(debug_info, bv, DIE)

    while len(unknown_type_DIEs) > 0:
        # Process unknown DIEs until the queue is empty
        unknown_type_die = unknown_type_DIEs.popleft()
        if record_data_type(debug_info, bv, unknown_type_die) is False:
            unknown_type_DIEs.append(unknown_type_die)

    # iter CUs for functions
    for CU in dwarf_info.iter_CUs():
        for DIE in CU.get_top_DIE().iter_children():
            if DIE.tag == "DW_TAG_subprogram":
                record_function(debug_info, bv, DIE)

    # iter CUs for data_variables
    for CU in dwarf_info.iter_CUs():
        for DIE in CU.get_top_DIE().iter_children():
            if DIE.tag == "DW_TAG_variable":
                record_data_variable(debug_info, bv, DIE, CU)

    file_obj.close()
    """
    debug_info.add_type("name", bn.types.Type.int(4, True))
    debug_info.add_data_variable(0x1234, bn.types.Type.int(4, True), "name")
    debug_info.add_data_variable(0x4321, bn.types.Type.int(4, True))  # Names are optional
    function_info = bn.debuginfo.DebugFunctionInfo("short_name", "full_name", "raw_name", 0xdead1337,
                                                   bn.types.Type.int(4, False), [])
    debug_info.add_function(function_info)"""


bn.debuginfo.DebugInfoParser.register("dwarf-debug-parser", is_valid, parse_info)
