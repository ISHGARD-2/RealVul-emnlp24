
ext_dict = {
    "php": ['.php', '.php3', '.php4', '.php5', '.php7', '.pht', '.phs', '.phtml', '.inc'],
}

NEWLINE_FLAGS = ["<?php", "{", "}", ";"]

# built in function names
code = open("configs/buildin_func.txt", "r", encoding="utf-8").read()
BUILTIN_FUNC = code.split('\n')

REGEX = {
    'functions': r'(?:function\s+)(\w+)\s*\(',
    'string': r"(?:['\"])(.*)(?:[\"'])",
    'assign_string': r"({0}\s?=\s?[\"'](.*)(?:['\"]))",
    'annotation': r"(#|\\\*|\/\/|\*)+",
    'variable': r'(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)',
    'assign_out_input': r'({0}\s?=\s?.*\$_[GET|POST|REQUEST|SERVER|COOKIE]+(?:\[))'
}

