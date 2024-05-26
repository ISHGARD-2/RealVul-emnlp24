import json
import os

from configs.const import INPUT_VARIABLES
from configs.settings import DATA_PATH
from utils.func_json import read_json, write_json
from utils.utils import match_pair, replace_str
from rules.php.CVI_10001 import CVI_10001

FILE_PATH = os.path.join(DATA_PATH, 'SARD', 'SARD_php_vulnerability_89.json')

FILTER_STR = ['$array[]', 'sprintf']


def delete_useless_sample(json_data):
    count = 1
    output_data = []
    for i, slice in enumerate(json_data):
        code = slice['slice']

        append = False
        if "$_GET" in code:
            append = True
        for str in FILTER_STR:
            if str in code:
                append = False
                break

        if append:
            slice['id'] = count
            count += 1
            output_data.append(slice)

    return output_data


def rename_input_vars():
    fp = open(FILE_PATH, 'r')
    json_data = json.load(fp)
    fp.close()

    for i, slice in enumerate(json_data):
        code = slice['renamed_code']
        for var in INPUT_VARIABLES:
            if var == '$_GET':
                continue

            if var in code:
                code = code.replace(var, '$_GET')

        json_data[i]['renamed_code'] = code

    fp = open(FILE_PATH, 'w')
    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()


def add_comment():
    fp = open(FILE_PATH, 'r')
    json_data = json.load(fp)
    fp.close()

    for i, slice in enumerate(json_data):
        code = slice['renamed_code']

        lr_pos = match_pair(code, 'echo', ';')
        if lr_pos is None:
            exit()
        l_pos = lr_pos[0]
        r_pos = lr_pos[1] + 1

        rule = CVI_10001()
        param = rule.main(code[l_pos: r_pos])

        if not param or len(param) != 1:
            exit()

        str_list = list(code)
        str_list.insert(r_pos, '\t\t//sink point: ' + param[0] + ';')
        new_code = ''.join(str_list)
        new_code = new_code.replace('<?php', '<?php\n// php code:')

        json_data[i]['renamed_code'] = new_code

    fp = open(FILE_PATH, 'w')
    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()


def rename_var_and_str():
    fp = open(FILE_PATH, 'r')
    json_data = json.load(fp)
    fp.close()

    for i, slice in enumerate(json_data):
        code = slice['renamed_code']

        # params
        rule = CVI_10001()
        params = rule.main(code)
        params = list(set(params))
        params = sorted(params, key=lambda i: len(i), reverse=True)
        # output_param
        lr_pos = match_pair(code, '//sink point:', ';')
        if lr_pos is None:
            exit()
        l_pos = lr_pos[0]
        r_pos = lr_pos[1] + 1

        rule = CVI_10001()
        param = rule.main(code[l_pos: r_pos])
        if not param or len(param) != 1:
            exit()
        output_para = param[0]

        count = 1
        for par in params:
            if par in INPUT_VARIABLES:
                continue

            if par == output_para:
                code = code.replace(par, '$taint')
            else:
                if '$taint'.startswith(par):
                    exit()
                code = code.replace(par, '$var' + str(count))
                count += 1

        # rename string
        echo_count = code.count('echo ')
        if echo_count > 1:
            exit()

        lr_pos = match_pair(code, 'echo', ';')
        if lr_pos is None:
            exit()
        l_pos = lr_pos[0]
        r_pos = lr_pos[1] + 1

        tmp_code = code[l_pos: r_pos]

        new_tmp_code = replace_str(tmp_code)
        code = code.replace(tmp_code, new_tmp_code)

        json_data[i]['renamed_code'] = code

    fp = open(FILE_PATH, 'w')
    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()


def edit_sample_id():
    fp = open(FILE_PATH, 'r')
    json_data = json.load(fp)
    fp.close()

    for i, slice in enumerate(json_data):
        json_data[i]['id'] = i + 1

    fp = open(FILE_PATH, 'w')
    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()


if __name__ == '__main__':
    json_data = read_json(FILE_PATH)

    output_data = delete_useless_sample(json_data)

    write_json(output_data, FILE_PATH)
