from elftools import dwarf


def get_attribute_str_value(die: dwarf.die, attribute_key: str):
    return die.attributes[attribute_key].value.decode("utf-8")

