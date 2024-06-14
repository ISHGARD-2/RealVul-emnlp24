import difflib
import json
import operator
import os
import re

from tqdm import tqdm

from configs.const import INPUT_VARIABLES, SYNTHESIS_LEN
from configs.settings import DATA_PATH
from rules.php.CVI_10001 import CVI_10001
from utils.log import logger
from utils.my_utils import match_pair, replace_str
from phply.phplex import lexer
from phply.phpparse import make_parser


# edit id
file_id = '_all'
RAW_PATH = DATA_PATH + '\\CVI_10001\\dataset_raw'+str(file_id)+'.json'
OUT_PATH = DATA_PATH + '\\CVI_10001\\dataset_out'+str(file_id)+'.json'
OUT_UNIQUE_PATH = DATA_PATH + '\\CVI_10001\\dataset_out_all_unique.json'
SYNTHESIS_PATH = DATA_PATH + '\\CVI_10001\\dataset_synthesis_79.json'
TEST_PATH = DATA_PATH + '\\CVI_10001\\test_set\\dataset_test.json'

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

def edit_sample_id(path, issynthesis=False):
    fp = open(path, 'r')
    json_data = json.load(fp)
    fp.close()

    for i, slice in enumerate(json_data):
        if not issynthesis:
            json_data[i]['id'] = i + 1
            json_data[i]['CVE_database_id'] = int(slice['file_name'].split('_')[1])
        else:
            file_name = slice['file_name'].split('\\')[-1]
            if 'SARD' in file_name:
                raw_dataset = 'SARD'
                raw_sample_id = int(file_name.split(raw_dataset)[1].split('_')[2])
            elif 'crossvul' in file_name:
                raw_dataset = 'crossvul'
                raw_sample_id = int(file_name.split(raw_dataset)[1].split('_')[2])
            else:
                raise Exception

            json_data[i]['id'] = i + 1
            json_data[i]['file_name'] = file_name
            json_data[i]['raw_dataset'] = raw_dataset
            json_data[i]['raw_sample_id'] = raw_sample_id



    fp = open(path, 'w')
    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()

def rename_input_vars():
    fp = open(OUT_PATH, 'r')
    json_data = json.load(fp)
    fp.close()

    fp = open(OUT_PATH, 'w')

    for i, slice in enumerate(json_data):
        code = slice['slice']
        for var in INPUT_VARIABLES:
            if var == '$_GET':
                continue

            if var in code:
                code = code.replace(var, '$_GET')

        json_data[i]['slice'] = code


    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()

def rename_all_var_and_str0(json_data, twice=False):
    out = []
    for i, slice in enumerate(json_data):
        code = slice['slice']

        # params
        rule = CVI_10001()
        params = rule.main(code)
        if not params:
            continue
        params = list(set(params))
        params = sorted(params, key=lambda i: len(i), reverse=True)

        # output_param
        lr_pos = match_pair(code, '//sink point:', ';')
        if lr_pos is None:
            continue
        l_pos = lr_pos[0]
        r_pos = lr_pos[1] + 1

        rule = CVI_10001()
        param = rule.main(code[l_pos: r_pos])
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
        if echo_count > 1:
            continue

        lr_pos = match_pair(code, 'echo', ';')
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

def rename_all_var_and_str():
    fp = open(OUT_PATH, 'r')
    json_data = json.load(fp)
    fp.close()

    json_data = rename_all_var_and_str0(json_data)

    fp = open(OUT_PATH, 'w')
    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()


def remove_similar_slice(in_path, out_path, threshold=0.95):
    fp = open(in_path, 'r')
    json_data = json.load(fp)
    fp.close()
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
                if similarity > threshold and label == label_saved:
                    # print('#'*30 +'\n{v1}\n{v2}\n'.format(v1=project[i]['renamed_slice'], v2=unique_samples[j]['renamed_slice']))
                    unique = False
                    break
            if unique:
                unique_samples.append(project[i])

        output_data += unique_samples
        print('CVE_database_id: {v1}\traw_count: {v2}\tnow count: {v3}'.format(v1=str(key), v2=str(len(project)), v3=len(unique_samples)))

    fp = open(out_path, 'w')
    output_data = json.dumps(output_data)
    fp.write(output_data)
    fp.close()


def gen_test_set(in_path, out_path):
    fp = open(in_path, 'r')
    json_data = json.load(fp)
    fp.close()

    data_list = []
    for sample in json_data:
        if len(sample['renamed_slice'] ) > SYNTHESIS_LEN or sample['CVE_database_id']>4500:
            data_list.append(sample)

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
                if similarity > threshold and label == label_saved:
                    # print('#'*30 +'\n{v1}\n{v2}\n'.format(v1=project[i]['renamed_slice'], v2=unique_samples[j]['renamed_slice']))
                    unique = False
                    break
            if unique:
                unique_samples.append(project[i])

        output_data += unique_samples
        print('CVE_database_id: {v1}\traw_count: {v2}\tnow count: {v3}'.format(v1=str(key), v2=str(len(project)), v3=len(unique_samples)))

    fp = open(out_path, 'w')
    output_data = json.dumps(output_data)
    fp.write(output_data)
    fp.close()



if __name__ == '__main__':
    # rename_input_vars()
    # rename_all_var_and_str()
    # remove_similar_slice()
    # edit_sample_id(OUT_UNIQUE_PATH)
    # remove_similar_slice(SYNTHESIS_PATH, SYNTHESIS_PATH)
    gen_test_set(SYNTHESIS_PATH, TEST_PATH)
