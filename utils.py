from typing import Optional

import binaryninja as bn
from elftools import dwarf


def get_attribute_str_value(die: dwarf.die, attribute_key: str):
    return die.attributes[attribute_key].value.decode("utf-8")


# If return type is none then the DIE should be added to unknown_type_DIEs
def check_if_type_str_exists(type_str: str, bv: bn.binaryview.BinaryView) -> Optional[bn.Type]:
    try:
        return bv.parse_type_string(type_str)[0]  # Gets bn.types.Type from tuple
    except SyntaxError:
        # Type is unknown to the current binary view
        return None
