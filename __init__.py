import pprint
from typing import Optional

import binaryninja as bn
from elftools import dwarf
from elftools.dwarf import descriptions
from elftools.elf import elffile

from .utils import get_attribute_str_value


def get_pointer_type(data_type_die: dwarf.die, bv: bn.binaryview.BinaryView, pointer_level: int = 1) -> \
        Optional[tuple[str, bn.types.Type]]:
    # Check for void pointer
    if "DW_AT_type" not in data_type_die.attributes:
        return ("void" + ("*" * pointer_level)), bv.parse_type_string("void" + ("*" * pointer_level))[0]

    child_type_die = data_type_die.get_DIE_from_attribute("DW_AT_type")
    if child_type_die.tag == "DW_TAG_pointer_type":
        return get_pointer_type(child_type_die, bv, pointer_level + 1)

    elif child_type_die.tag == "DW_TAG_typedef":
        new_type_str = get_attribute_str_value(child_type_die, "DW_AT_name")
        new_type_str += "*" * pointer_level
        bv_type = recover_data_type(bv, child_type_die)
        if bv_type is None:
            return None
        else:
            return new_type_str, bv_type[1]

    elif child_type_die.tag == "DW_TAG_base_type":
        new_type_str = get_attribute_str_value(child_type_die, "DW_AT_name")
        new_type_str += "*" * pointer_level
        return new_type_str, recover_data_type(bv, child_type_die)[1]
    elif child_type_die.tag == "DW_TAG_structure_type":
        new_type_str = get_attribute_str_value(child_type_die, "DW_AT_name")
        new_structure = recover_data_type(bv, child_type_die)[1]
        bn_pointer_to_struct = bn.types.Type.pointer(bv.arch, new_structure)
        new_type_str += "*" * pointer_level
        return new_type_str, bn_pointer_to_struct
    else:
        bn.log_error(f"Unknown child_type TAG in get_pointer_type: {child_type_die.tag}")
        return None


# Recover Data Type and return a tuple to the calling function for further construction or recording
def recover_data_type(bv: bn.binaryview.BinaryView, data_type_die: dwarf.die) -> Optional[tuple[str, bn.types.Type]]:
    if data_type_die.tag == "DW_TAG_pointer_type":
        # pointer_type DIEs don't have a name attribute
        pointer_type = get_pointer_type(data_type_die, bv)
        if pointer_type is None:
            return None
        else:
            return pointer_type

    elif data_type_die.tag == "DW_TAG_array_type":
        array_core_type_die = data_type_die.get_DIE_from_attribute("DW_AT_type")
        array_core_type: tuple[str, bn.Type] = recover_data_type(bv, array_core_type_die)
        if array_core_type is None:
            bn.log_error(f"Failed to get array_core_type for DIE @ offset: {hex(data_type_die.offset)}")
        # Get array size
        array_size = 1
        for sub_range_die in data_type_die.iter_children():
            # Verify if we're in a subrange_type DIE
            if sub_range_die.tag != "DW_TAG_subrange_type":
                bn.log_error(f"Unknown array subrange_type, TAG: {sub_range_die.tag}")
                return None
            # Check for DW_AT_upper_bound or DW_AT_count
            if "DW_AT_count" in sub_range_die.attributes:
                array_size = sub_range_die.attributes["DW_AT_count"].value
            elif "DW_AT_upper_bound" in sub_range_die.attributes:
                array_size = sub_range_die.attributes["DW_AT_upper_bound"].value
            else:
                bn.log_error(f"DW_AT_count or DW_AT_upper_bound not found in DIE @ {hex(sub_range_die.offset)}")
                return None
        array_type = bn.types.Type.array(array_core_type[1], array_size)
        return array_type.get_string(), array_type

    elif data_type_die.tag == "DW_TAG_structure_type":
        # Build structure iteratively
        new_struct = bn.types.StructureBuilder.create()
        new_struct_name = ""
        if "DW_AT_name" in data_type_die.attributes:
            new_struct_name = get_attribute_str_value(data_type_die, "DW_AT_name")

        for member_die in data_type_die.iter_children():
            struct_mem_name = get_attribute_str_value(member_die, "DW_AT_name")
            struct_mem_type_die = member_die.get_DIE_from_attribute("DW_AT_type")
            struct_mem_type = recover_data_type(bv, struct_mem_type_die)
            new_struct.append(struct_mem_type[1], struct_mem_name)

        return new_struct_name, bn.types.Type.structure_type(new_struct)
    elif data_type_die.tag == "DW_TAG_typedef":
        referred_data_type_die = data_type_die.get_DIE_from_attribute("DW_AT_type")
        referred_data_type = recover_data_type(bv, referred_data_type_die)
        referred_data_type_name = get_attribute_str_value(data_type_die, "DW_AT_name")

        return referred_data_type[0], bn.types.Type.named_type_from_type(bn.QualifiedName(referred_data_type_name),
                                                                         referred_data_type[1])
    elif data_type_die.tag == "DW_TAG_base_type":
        # Core language data type. BN is almost certain to be able to recognize it
        base_type_name = get_attribute_str_value(data_type_die, "DW_AT_name")
        return base_type_name, bv.parse_type_string(base_type_name)[0]
    elif data_type_die.tag == "DW_TAG_const_type":
        referred_data_type_die = data_type_die.get_DIE_from_attribute("DW_AT_type")
        data_type_name, data_type = recover_data_type(bv, referred_data_type_die)
        return data_type_name, data_type

    else:
        bn.log_error(f"Attempted to recover unknown data_type in DIE: {data_type_die.tag}")
    return None


def record_function(debug_info: bn.debuginfo.DebugInfo, bv: bn.binaryview.BinaryView, func_die: dwarf.die) -> bool:
    # Grab return type
    ret_type = bn.types.Type.void()
    ret_type_name = ret_type.get_string()
    if "DW_AT_type" in func_die.attributes:
        type_die = func_die.get_DIE_from_attribute("DW_AT_type")
        ret_type_name, ret_type = recover_data_type(bv, type_die)

    debug_info.add_type(ret_type_name, ret_type)

    func_parameters = []
    for child_die in func_die.iter_children():
        # Sanity check if the child is a DW_TAG_formal_parameter
        if child_die.tag != "DW_TAG_formal_parameter":
            continue
        param_name = get_attribute_str_value(child_die, "DW_AT_name")
        param_data_type = bn.types.Type.pointer(bv.arch, bn.types.Type.void())
        # Sanity check if the child has a DW_AT_type attribute
        if "DW_AT_type" in child_die.attributes:
            bn.log_debug(f"Looking at DW_AT_type for name: {param_name}")
            pprint.pp(child_die)
            param_data_type_die = child_die.get_DIE_from_attribute("DW_AT_type")
            param_type_name, param_data_type = recover_data_type(bv, param_data_type_die)
            debug_info.add_type(param_type_name, param_data_type)

        func_parameters.append((param_name, param_data_type))

    # Recover function parameter names and types
    function_info = bn.debuginfo.DebugFunctionInfo(
        # Function parameter recovery is not available as it is broken in the BN core.
        full_name=get_attribute_str_value(func_die, 'DW_AT_name'), address=func_die.attributes["DW_AT_low_pc"].value,
        return_type=ret_type, parameters=func_parameters
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
    if bv.view_type != "ELF" or ".bndb" in bv.file.filename:
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
