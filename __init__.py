#!/usr/bin/env python3
# All that is required is to provide functions similar to "is_valid" and "parse_info" below, and call
# `binaryninja.debuginfo.DebugInfoParser.register` with a name for your parser; your parser will be made
# available for all valid binary views, with the ability to parse and apply debug info to existing BNDBs.
import binaryninja as bn
from elftools import dwarf
from elftools.dwarf import descriptions
from elftools.elf import elffile


def get_attribute_str_value(die: dwarf.die, attribute_key: str):
    return die.attributes[attribute_key].value.decode("utf-8")


def record_function(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, func_die: dwarf.die):
    bn.log_debug(
        f"Recording function: {get_attribute_str_value(func_die, 'DW_AT_name')} at addr {hex(func_die.attributes['DW_AT_low_pc'].value)}")
    function_info = bn.debuginfo.DebugFunctionInfo(
        full_name=get_attribute_str_value(func_die, 'DW_AT_name'), address=func_die.attributes["DW_AT_low_pc"].value,
    )
    debug_info.add_function(function_info)


def record_data_variable(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, variable_die: dwarf.die,
                         CU: dwarf.compileunit.CompileUnit):
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
    else:
        bn.log_error(f"Unknown type_die encountered: {type_die.tag}")
        return

    # Get location of data var in memory
    expr_dump_obj = dwarf.descriptions.ExprDumper(CU.structs)
    location_str = expr_dump_obj.dump_expr(variable_die.attributes['DW_AT_location'].value, CU.cu_offset)
    address_str = location_str.split(' ', 1)[1]
    address = int(address_str, 16)

    bn.log_debug(f"Creating data var: {name} @ {address} with type: {data_var_type.get_string()}")
    debug_info.add_data_variable(address, data_var_type, name)


def record_struct(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, struct_die: dwarf.die):
    if 'DW_AT_name' not in struct_die.attributes:
        # This is a typedef-ed struct. Will be handled in the future
        return

    new_struct = bn.StructureBuilder.create()
    bn.log_debug(f"Examining struct: {get_attribute_str_value(struct_die, 'DW_AT_name')}")
    # Iterate through stuct members
    for struct_die_member in struct_die.iter_children():
        if 'DW_AT_name' not in struct_die_member.attributes:
            bn.log_error(
                f"Failed to parse struct: {get_attribute_str_value(struct_die, 'DW_AT_name')}. Anonymous union detected")
            continue

        # fetch die with dwarf type for member
        member_type_dwarf = struct_die_member.get_DIE_from_attribute("DW_AT_type")
        bn.log_debug(f"Parsing struct member: {get_attribute_str_value(struct_die_member, 'DW_AT_name')}")

        # Check if DW_TAG_base_type or DW_TAG_typedef
        if member_type_dwarf.tag == "DW_TAG_typedef":
            # Must follow typedef. Currently, handle typedefs to primitive types
            member_type = bv.parse_type_string(get_attribute_str_value(member_type_dwarf, 'DW_AT_name'))[0]
            new_struct.append(member_type, get_attribute_str_value(struct_die_member, 'DW_AT_name'))
        elif member_type_dwarf.tag == "DW_TAG_base_type":
            # Can grab name, encoding, and byte size
            member_type = bv.parse_type_string(get_attribute_str_value(member_type_dwarf, 'DW_AT_name'))[0]
            new_struct.append(member_type, get_attribute_str_value(struct_die_member, 'DW_AT_name'))
        elif member_type_dwarf.tag == "DW_TAG_array_type":
            array_type = member_type_dwarf.get_DIE_from_attribute("DW_AT_type")
            array_type = bv.parse_type_string(get_attribute_str_value(array_type, 'DW_AT_name'))[0]
            array_size = 1  # Placeholder until DW_TAG_subrange_type is found

            # Access DW_TAG_subrange_type DIE for ArraySize
            for child in member_type_dwarf.iter_children():
                if child.tag == "DW_TAG_subrange_type":
                    array_size = child.attributes['DW_AT_count'].value

            bn.log_debug(f"Found struct array - Type: {array_type} Size: {array_size}")
            member_type = bn.types.Type.array(array_type, array_size)
            new_struct.append(member_type, get_attribute_str_value(struct_die_member, 'DW_AT_name'))
            continue
        else:
            bn.log_error(f"Failed to parse struct member. Unknown tag: {member_type_dwarf.tag}")

    bn.log_debug(f"Recording struct: {get_attribute_str_value(struct_die, 'DW_AT_name')}")
    debug_info.add_type(get_attribute_str_value(struct_die, 'DW_AT_name'), bn.Type.structure_type(new_struct))


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
            elif DIE.tag == "DW_TAG_structure_type":
                record_struct(debug_info, bv, DIE)
            elif DIE.tag == "DW_TAG_variable":
                record_data_variable(debug_info, bv, DIE, CU)
            else:
                bn.log_error(f"Unknown DIE tag: {DIE.tag}")

    file_obj.close()
    """
    debug_info.add_type("name", bn.types.Type.int(4, True))
    debug_info.add_data_variable(0x1234, bn.types.Type.int(4, True), "name")
    debug_info.add_data_variable(0x4321, bn.types.Type.int(4, True))  # Names are optional
    function_info = bn.debuginfo.DebugFunctionInfo("short_name", "full_name", "raw_name", 0xdead1337,
                                                   bn.types.Type.int(4, False), [])
    debug_info.add_function(function_info)"""


bn.debuginfo.DebugInfoParser.register("dwarf-debug-parser", is_valid, parse_info)
