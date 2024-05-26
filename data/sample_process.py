import difflib
import json
import operator
import os
import re

from tqdm import tqdm

from configs.const import INPUT_VARIABLES, SYNTHESIS_LEN
from configs.settings import DATA_PATH
from rules.php.CVI_10001 import CVI_10001
from utils.func_json import read_json, write_json
from utils.log import logger
from utils.utils import match_pair, replace_str, match_params, slilce_check_syntax
from phply.phplex import lexer
from phply.phpparse import make_parser

def add_comment(code, match_str):
    """
    CWE_79: match echo ... ;
    CWE_89: match $query = ... ;
    """
    lr_pos = match_pair(code, match_str, ';')
    if lr_pos is None:
        raise Exception
    l_pos = lr_pos[0]+len(match_str)
    r_pos = lr_pos[1] + 1

    param = match_params(code[l_pos: r_pos])

    if not param or len(param) != 1:
        raise Exception

    str_list = list(code)
    str_list.insert(r_pos, '\t\t//sink point: ' + param[0] + ';')
    new_code = ''.join(str_list)
    new_code = new_code.replace('<?php', '<?php\n// php code:')

    return new_code


def save_sample_to_file(path):
    fp = open(path, 'r')
    json_data = json.load(fp)
    fp.close()
    directory = DATA_PATH + '\\CVI_10001\\source_code\\'
    if not os.path.exists(directory):
        os.makedirs(directory)

    for slice in json_data:
        raw_file_name = slice['file_name']
        raw_id = slice['id']
        raw_code = slice['slice']

        fphp = open(directory+raw_file_name[:-4]+'__'+str(raw_id)+'.php', 'w')
        fphp.write(raw_code)
        fphp.close()

def edit_sample_id(json_data, issynthesis=False, isSARD=False):
    for i, slice in enumerate(json_data):
        if not issynthesis:
            if isSARD:
                json_data[i]['id'] = i + 1
            else:
                json_data[i]['id'] = i + 1
                json_data[i]['CVE_database_id'] = int(slice['file_name'].split('_')[1])
        else:
            file_name = slice['file_name'].split('\\')[-1]
            if isSARD:
                raw_dataset = 'SARD'
                raw_sample_id = int(file_name.split(raw_dataset)[1].split('_')[2])
            else:
                raw_dataset = 'crossvul'
                raw_sample_id = int(file_name.split(raw_dataset)[1].split('_')[2])

            json_data[i]['id'] = i + 1
            json_data[i]['file_name'] = file_name
            json_data[i]['raw_dataset'] = raw_dataset
            json_data[i]['raw_sample_id'] = raw_sample_id


    return json_data


def check_syntax(json_data, key='renamed_slice'):
    out = []
    for i, slice in enumerate(json_data):
        code = slice[key]
        if not slilce_check_syntax(code):
            continue
        else:
            out.append(slice)
    return out


def rename_input_vars(json_data):

    for i, slice in enumerate(json_data):
        code = slice['slice']
        for var in INPUT_VARIABLES:
            if var == '$_GET':
                continue

            if var in code:
                code = code.replace(var, '$_GET')

        json_data[i]['slice'] = code


    return json_data

def rename_all_var_and_str_79(json_data, twice=False, isSARD=False):
    out = []
    for i, slice in enumerate(json_data):
        code = slice['slice']

        # params
        params = match_params(code)
        if not params:
            raise Exception
        params = list(set(params))
        params = sorted(params, key=lambda i: len(i), reverse=True)

        # output_param
        lr_pos = match_pair(code, '//sink point:', ';')
        if lr_pos is None:
            raise Exception

        l_pos = lr_pos[0]
        r_pos = lr_pos[1] + 1

        param = match_params(code[l_pos: r_pos])
        if not param or len(param) != 1:
            continue
        output_para = param[0]

        if twice:
            for j, par in enumerate(params):
                if par.startswith('$var'):
                    code = code.replace(par, '$tmp_to_change' + str(j))
                    params[j] = '$tmp_to_change' + str(j)

        count = 1
        for par in params:
            if par in INPUT_VARIABLES:
                continue

            if par == output_para:
                code = code.replace(par, '$taint')
            else:
                if '$taint'.startswith(par) or '$var'.startswith(par):
                    continue

                var_base = '$var'
                code = code.replace(par, var_base+str(count))
                count += 1


        # rename string
        echo_count = code.count('echo ')
        if echo_count > 1 or echo_count == 0:
            continue

        lr_pos = match_pair(code, 'echo ', ';')
        if lr_pos is None:
            continue
        l_pos = lr_pos[0]
        r_pos = lr_pos[1] + 1

        # print('#'*100)
        # print('\n{}\n'.format(code))

        pre_code = code[:l_pos]
        tmp_code = code[l_pos: r_pos]
        suf_code = code[r_pos:]

        new_pre_code = replace_str(pre_code,  match_html=True)

        new_tmp_code = replace_str(tmp_code)

        code = new_pre_code+new_tmp_code+suf_code

        # print('\n{}\n'.format(code))

        json_data[i]['renamed_slice'] = code
        out.append(json_data[i])

    return out


def rename_all_var_and_str_89(json_data, twice=False, isSARD=False):
    out = []
    for i, slice in enumerate(json_data):
        code = slice['slice']

        if isSARD:
            code_lines = code.split('\n')
            code = ""
            for line in code_lines:
                if 'echo ' in line or 'mysql_select_db' in line or 'mysql_connect' in line:
                    continue
                code += line+'\n'
                if 'mysql_query' in line:
                    break
            code = add_comment(code, '$query = ')

        # rename string
        query_count = code.count('$query = ')
        if query_count > 1:
            continue

        lr_pos = match_pair(code, '$query = ', ';')
        if lr_pos is None:
            continue
        l_pos = lr_pos[0] + 9
        r_pos = lr_pos[1] + 1

        pre_code = code[:l_pos]
        tmp_code = code[l_pos: r_pos].replace('\n', '')
        suf_code = code[r_pos:]

        new_pre_code = replace_str(pre_code, match_html=True)
        new_tmp_code = replace_str(tmp_code)
        code = new_pre_code + new_tmp_code + suf_code

        # params
        params = match_params(code)
        if not params:
            raise Exception
        params = list(set(params))
        params = sorted(params, key=lambda i: len(i), reverse=True)

        # output_param
        lr_pos = match_pair(code, '//sink point:', ';')
        if lr_pos is None:
            continue

        l_pos = lr_pos[0]
        r_pos = lr_pos[1] + 1

        param = match_params(code[l_pos: r_pos])
        if not param or len(param) != 1:
            continue
        output_para = param[0]

        if twice:
            for j, par in enumerate(params):
                if par.startswith('$var'):
                    code = code.replace(par, '$tmp_to_change' + str(j))
                    params[j] = '$tmp_to_change' + str(j)

        count = 1
        for par in params:
            if par in INPUT_VARIABLES:
                continue

            if par == output_para:
                code = code.replace(par, '$taint')
            else:
                if '$taint'.startswith(par) or '$var'.startswith(par):
                    continue

                var_base = '$var'
                code = code.replace(par, var_base+str(count))
                count += 1

        # print('\n{}\n'.format(code))

        json_data[i]['renamed_slice'] = code
        out.append(json_data[i])
    return out


def remove_similar_slice(json_data, threshold=1):
    data_list = {}
    for sample in json_data:
        CVE_database_id = sample['CVE_database_id']
        if str(CVE_database_id) not in data_list.keys():
            data_list[str(CVE_database_id)] = []
        data_list[str(CVE_database_id)].append(sample)

    output_data = []
    for key in tqdm(data_list):
        project = data_list[key]
        unique_samples = []
        for i in range(len(project)):
            sample = project[i]['renamed_slice']
            sample = re.sub('\s|\t|\n','',sample)
            label = project[i]['label']

            unique = True
            for j in range(len(unique_samples)):
                sample_saved = unique_samples[j]['renamed_slice']
                sample_saved = re.sub('\s|\t|\n', '', sample_saved)
                label_saved = unique_samples[j]['label']

                similarity = difflib.SequenceMatcher(None, sample, sample_saved).quick_ratio()
                if similarity >= threshold and label == label_saved:
                    # print('#'*30 +'\n{v1}\n{v2}\n'.format(v1=project[i]['renamed_slice'], v2=unique_samples[j]['renamed_slice']))
                    unique = False
                    break
            if unique:
                unique_samples.append(project[i])

        output_data += unique_samples
        print('CVE_database_id: {v1}\traw_count: {v2}\tnow count: {v3}'.format(v1=str(key), v2=str(len(project)), v3=len(unique_samples)))

    return output_data


# def gen_test_set(in_path, out_path):
#     fp = open(in_path, 'r')
#     json_data = json.load(fp)
#     fp.close()
#
#     data_list = []
#     for sample in json_data:
#         if len(sample['renamed_slice'] ) > SYNTHESIS_LEN or sample['CVE_database_id']>4500:
#             data_list.append(sample)
#
#     output_data = []
#     for key in tqdm(data_list):
#         project = data_list[key]
#         unique_samples = []
#         for i in range(len(project)):
#             sample = project[i]['renamed_slice']
#             sample = re.sub('\s|\t|\n','',sample)
#             label = project[i]['label']
#
#             unique = True
#             for j in range(len(unique_samples)):
#                 sample_saved = unique_samples[j]['renamed_slice']
#                 sample_saved = re.sub('\s|\t|\n', '', sample_saved)
#                 label_saved = unique_samples[j]['label']
#
#                 similarity = difflib.SequenceMatcher(None, sample, sample_saved).quick_ratio()
#                 if similarity > threshold and label == label_saved:
#                     # print('#'*30 +'\n{v1}\n{v2}\n'.format(v1=project[i]['renamed_slice'], v2=unique_samples[j]['renamed_slice']))
#                     unique = False
#                     break
#             if unique:
#                 unique_samples.append(project[i])
#
#         output_data += unique_samples
#         print('CVE_database_id: {v1}\traw_count: {v2}\tnow count: {v3}'.format(v1=str(key), v2=str(len(project)), v3=len(unique_samples)))
#
#     fp = open(out_path, 'w')
#     output_data = json.dumps(output_data)
#     fp.write(output_data)
#     fp.close()



if __name__ == '__main__':
    # edit id
    file_id = '_all'
    rule = 'CVI_10002'
    CWE = '89'

    #path
    RAW_PATH = DATA_PATH + '\\' + rule + '\\CVI_10002_dataset.json'
    SARD_PATH_89 = DATA_PATH + '\\SARD_php_vulnerability_89.json'

    OUT_PATH = DATA_PATH + '\\' + rule + '\\CVI_10002_dataset_out.json'
    OUT_UNIQUE_PATH = DATA_PATH + '\\' + rule + '\\dataset_out_all_unique.json'
    SYNTHESIS_PATH = DATA_PATH + '\\' + rule + '\\dataset_synthesis_79.json'
    TEST_PATH = DATA_PATH + '\\' + rule + '\\test_set\\dataset_test.json'

    json_data = read_json(OUT_PATH)
    #
    # json_data = rename_input_vars(json_data)
    # json_data = rename_all_var_and_str_89(json_data, isSARD=False)
    # json_data = edit_sample_id(json_data, isSARD=False)
    # json_data = remove_similar_slice(json_data,threshold=1)
    # json_data = edit_sample_id(json_data)
    #
    # write_json(json_data, OUT_PATH)
    json_data = edit_sample_id(json_data, isSARD=False)
    json_data = check_syntax(json_data)
    write_json(json_data, OUT_PATH)
    # remove_similar_slice()
    # edit_sample_id(OUT_UNIQUE_PATH)
    # remove_similar_slice(SYNTHESIS_PATH, SYNTHESIS_PATH)
    # gen_test_set(SYNTHESIS_PATH, TEST_PATH)
