import os.path

from configs.settings import CONFIG_PATH

ext_dict = {
    "php": ['.php', '.php3', '.php4', '.php5', '.php7', '.pht', '.phs', '.phtml', '.inc'],
}

NEWLINE_FLAGS = ["<?php", "{", "}", ";"]

# built in function names
code = open(os.path.join(CONFIG_PATH, 'buildin_func.txt'), "r", encoding="utf-8").read()
BUILTIN_FUNC = code.split('\n')

REGEX = {
    'functions': r'(?:function\s+)(\w+)\s*\(',
    'assign_string': r"({0}\s?=\s?[\"'](.*)(?:['\"]))",
    'annotation': r"(#|\\\*|\/\/|\*)+",
    'variable': r'(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)',
    'assign_out_input': r'({0}\s?=\s?.*\$_[GET|POST|REQUEST|SERVER|COOKIE]+(?:\[))'
}

INPUT_VARIABLES = [
    '$_GET',
    '$_POST',
    '$_REQUEST',
    '$_COOKIE',
    '$_FILES',
    # '$_SESSION',
    '$HTTP_POST_FILES',
    '$HTTP_COOKIE_VARS',
    '$HTTP_REQUEST_VARS',
    '$HTTP_POST_VARS',
    '$HTTP_RAW_POST_DATA',
    '$HTTP_GET_VARS']

NOT_SUPPORT_STRING = [
    ('endif', True),
    ('<<<', True),
    ('??', True),
    # ('include ', True),
    # ('require', True)

]
SLICE_FILTER = [
    ('CATCH', True),
    ('catch', True),
    ('switch', True)

]

REG = {
    'functions': r'(?:function\s+)(\w+)\s*\(',
    'string': r"(?:['\"])(.*)(?:[\"'])",
    'assign_string': r"({0}\s?=\s?[\"'](.*)(?:['\"]))",
    'annotation': r"(#|\\\*|\/\/|\*)+",
    'variable': r'(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)',
    'assign_out_input': r'({0}\s?=\s?.*\$_[GET|POST|REQUEST|SERVER|COOKIE]+(?:\[))'
}

STRING_REPLACE_ELEMENT = [
    '.php',
    '<div', 'div>',
    '<input', 'input>',
    '<br', 'br>',
    '<li', 'li>',
    '<option', 'option>',
    '<a', 'a>',
    '<td', 'td>',
    '<html', 'html>',
    '<head', 'head>',
    '<title', 'title>',
    '<body', 'body',
    '<p', 'p>',
    '<img', 'img>',
    '<span', 'span>',
    '<ul', 'ul>',
    '<ol', 'ol>',
    '<table', 'table>',
    '<tr', 'tr>',
    '<form', 'formc>',
    '<form', 'form>',
    '<label', 'label>',
    '<th', 'th>',
    '<hr', 'hrc>',
    '<hr', 'hr>',
    '<style', 'style>',
    '<script', 'script>',
    '/>',
    '&nbsp;',
    '&lt;',
    '&gt;',
    '&amp;',
    '&quot;',
    '&apos;',
    '&cent;',
    '&pound;',
    '&yen;',
    '&euro;',
    '&sect;',
    '&copy;',
    '&reg;',
    '&reg;',
    '&times;',
    '&divide;'

]

SYNTHESIS_LEN = {
    '79':200,
    '89':250
}