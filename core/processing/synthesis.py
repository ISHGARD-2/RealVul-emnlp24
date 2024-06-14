import copy
import difflib
import json
import logging
import os
import random
import re
import threading
import time

from tqdm import tqdm

from configs.const import SYNTHESIS_LEN, INPUT_VARIABLES
from configs.settings import DATA_PATH, TMP_PATH, RESULT_PATH
from core import args_prepare, FuncCall, scan
from core.sampling.slicing import get_slice_from_flow
from core.processing.sample_preprocess import rename_all_var_and_str_89, rename_all_var_and_str_79
from utils.file import Directory, clear_slice
from utils.func_json import read_json, write_json
from utils.log import log, logger
from utils.my_utils import slilce_check_syntax


def process_direct_input(json_data, CWE, source='crossvul'):
    direct_input = []
    for slice in json_data:
        slice_dict = {}
        code = slice['renamed_slice']

        if len(code) > SYNTHESIS_LEN[CWE]:
            continue

        if source == 'crossvul':
            file_name = slice['file_name']
            id = slice['id']
            label = slice['label']
            slice_dict['file_name'] = source + '__' + label + '__' + file_name[:-4] + '__' + str(id)
            slice_dict['code'] = slice['renamed_slice']

        elif source == 'SARD':
            file_id = slice['file_id']
            raw_id = slice['id']
            label = slice['label']
            slice_dict['file_name'] = source + '__' + label + '__' + str(file_id) + '__' + str(raw_id)
            slice_dict['code'] = slice['renamed_slice']
        else:
            continue
        direct_input.append(slice_dict)
    return direct_input


def remove_similar_slice(json_data, unique_samples=None, threshold=1.0, key='slice', compare_label=False):
    if unique_samples is None:
        unique_samples = []
    else:
        unique_samples = unique_samples

    for i in range(len(json_data)):
        sample = json_data[i][key]
        sample = re.sub('\s|\t|\n', '', sample)

        unique = True
        for j in range(len(unique_samples)):
            if compare_label:
                label = json_data[i]['label']
                label_saved = unique_samples[j]['label']
                if label != label_saved:
                    continue

            sample_saved = unique_samples[j][key]
            sample_saved = re.sub('\s|\t|\n', '', sample_saved)

            similarity = difflib.SequenceMatcher(None, sample, sample_saved).quick_ratio()
            if similarity >= threshold:
                unique = False
                break
        if unique:
            unique_samples.append(json_data[i])
    return unique_samples


def func_prepare(SARD_data_path, crossvul_data_path, clear_target_directory, CWE):
    crossvul_sample_data = read_json(crossvul_data_path)
    SARD_sample_data = read_json(SARD_data_path)
    SARD_sample_data = remove_similar_slice(SARD_sample_data, key='renamed_slice',
                         compare_label=True, threshold=1.0)
    sample_CVE_list = [slice['CVE_database_id'] for slice in crossvul_sample_data]
    sample_CVE_list = list(set(sample_CVE_list))

    # raw files
    files, file_count, time_consume = Directory(clear_target_directory).collect_files()
    new_file_list = []
    for file in files[0][1]['list']:
        CVE_database_id = int(file.split('_')[1])
        if CVE_database_id not in sample_CVE_list:
            new_file_list.append(file)
    files[0][1]['list'] = new_file_list

    # raw function list and control flow
    clear_target_func = FuncCall(clear_target_directory, files)
    clear_target_func.main('test')

    sample_directory = os.path.join(TMP_PATH, 'source_code')

    direct_input = []
    direct_input += process_direct_input(crossvul_sample_data, CWE, source='crossvul')
    direct_input += process_direct_input(SARD_sample_data, CWE, source='SARD')
    files = [('php', {'count': len(direct_input), 'list': [s['file_name'] for s in direct_input]})]
    sample_func_call = FuncCall(sample_directory, files, input_mode='direct', direct_input=direct_input)
    sample_func_call.main('test')

    return sample_func_call, clear_target_func


def select_random_flow(control_flow, sample_count=None):
    sub_flow = control_flow.subnode

    # subnode mark
    if control_flow.name == 'if' and len(sub_flow) > 0 and sub_flow[-1].name == 'else':
        if random.randint(0, 1) == 1 and len(sub_flow) > 2:
            for i, flow in enumerate(sub_flow[:-1]):
                select_random_flow(flow)
            control_flow.set_flag()
        else:
            if len(sub_flow[-1].subnode) > 1:
                select_random_flow(sub_flow[-1])
                control_flow.set_flag()
    elif control_flow.name != 'others':
        if len(sub_flow) > 1:
            for i, flow in enumerate(sub_flow):
                select_random_flow(flow)
                if sample_count and sample_count + 8 < i:
                    break
            control_flow.set_flag()
    else:
        if ('echo ' not in control_flow.code
                and 'return ' not in control_flow.code
                and not re.search(r"[\"']+\s*(select|SELECT|insert|INSERT|update|UPDATE|DELETE|delete)\s+.*;",
                                  control_flow.code)):
            control_flow.set_flag()


def insert_code(func, sample_code_list, line_count=50):
    func_code_pre = '<?php\n'
    if func.func_name != 'root' and func.func_type != None:
        for i, par in enumerate(func.node_ast.params):
            func_code_pre += par.name + " = $_GET['input0" + str(i) + "'];\n"
    sample_count = len(sample_code_list)

    # select flow randomly
    control_flow = func.control_flow
    code_slice_flag = [0 for i in range(control_flow.all_code_position[-1]['position'][1])]

    select_random_flow(control_flow, sample_count)

    selected_func_code = get_slice_from_flow(control_flow, code_slice_flag, True)
    selected_func_code = clear_slice(selected_func_code)

    selected_func_code_list = selected_func_code.split('\n')


    if sample_count > len(selected_func_code_list) - 8 or sample_count > 10:
        return None

    # clear conflow flag
    control_flow.clear_flag()

    # generate insert position
    if len(selected_func_code_list) < 50:
        insert_max = len(selected_func_code_list)
    else:
        insert_max = 50
    insert_pos = random.sample(range(2, insert_max), len(sample_code_list));
    insert_pos = sorted(insert_pos)

    # insert
    for l in range(len(sample_code_list) - 1, -1, -1):
        selected_func_code_list.insert(insert_pos[l], '\n' + sample_code_list[l] + '\n')
    final_code = '\n'.join(selected_func_code_list)

    synthesis_code = func_code_pre + clear_slice(final_code)

    return synthesis_code


def synthesis_threading(function_list, special_rules, sample, sample_code, sample_code_list, insert_count, tmp_path,
                        threading_id=0):
    global direct_input
    for idx, func in enumerate(function_list):
        if not hasattr(func, 'control_flow'):
            continue

        tmp_direct_input = []

        # t1 = time.time()
        for i in range(insert_count * 2):
            if insert_count <= len(tmp_direct_input):
                break

            synthesis = dict()
            code = insert_code(func, sample_code_list)

            # check
            if code is None:
                continue
            if not slilce_check_syntax(code, log=False):
                continue

            synthesis['code'] = code
            synthesis['file_name'] = func.file + "__" + str(i) + "__" + sample.file + ".php"
            tmp_direct_input.append(synthesis)

        if len(tmp_direct_input) == 0:
            continue

        # t2 = time.time()
        files = [('php', {'count': len(tmp_direct_input), 'list': [s['file_name'] for s in tmp_direct_input]})]
        tmp_synthesis_func_call = FuncCall(tmp_path, files, input_mode='direct', direct_input=tmp_direct_input)
        tmp_synthesis_func_call.main('synthesis')

        # get snippets
        results = scan(tmp_synthesis_func_call, target_directory=tmp_path, store_path=None,
                       special_rules=special_rules, files=files,
                       mode='synthesis')
        results = results[list(results.keys())[0]]


        # remove similar snippet
        # t3 = time.time()
        unique_samples = remove_similar_slice(results, [{'slice': sample_code}], threshold=0.95)[1:]

        # t4 = time.time()

        # print(t2 - t1)
        # print(t3 - t2)
        # print(t4 - t3)
        direct_input += unique_samples


def synthesis(SARD_data_path, crossvul_data_path, clear_target_directory, CWE, insert_count=8):
    """
    clear_target_directory: clear project to be inserted
    insert_count: randomly insert K times
    line_count: insert the first Cth line of code

    synthesis file name:
        clear target file name -> cve_database_id
        crossvul:  (clear target file name) __ (synthesis id) __ crossvul __ (raw sample label) __ (corssvul raw sample file_name) __ (raw sample id)
        SARD: (clear target file name) __ (synthesis id) __ SARD __ (raw sample label) __ + (raw sample file_id) + __ + (raw sample id)
    """
    global direct_input

    if CWE == '79':
        special_rules = ['CVI_10001.py']
    elif CWE == '89':
        special_rules = ['CVI_10002.py']
    else:
        logger.error('[SYNTHESIS] not support rule')
        raise Exception

    # last dir name
    clear_target_lastdir = clear_target_directory.split('\\')[-1]

    synthesis_save_path = str(os.path.join(RESULT_PATH, 'synthesis', 'CWE-' + CWE))
    synthesis_tmp_path = str(os.path.join(TMP_PATH, 'synthesis', 'CWE-' + CWE, clear_target_lastdir))

    if not os.path.exists(synthesis_save_path):
        os.makedirs(synthesis_save_path)
    synthesis_save_path = str(os.path.join(synthesis_save_path, 'dataset_synthesis_' + CWE + '.json'))
    logger.info('[SYNTHESIS] save path: {}'.format(synthesis_save_path))

    if not os.path.exists(synthesis_tmp_path):
        os.makedirs(synthesis_tmp_path)

    sample_func_call, clear_target_func = func_prepare(SARD_data_path, crossvul_data_path, clear_target_directory, CWE)

    systhesis_sample_lists = []

    logger.info('[SYNTHESIS] insert samples ... ')
    for sample in tqdm(sample_func_call.function_list):
        # logger.info("[synthesis] {}".format(sample.file))
        if not hasattr(sample, 'control_flow'):
            continue

        sample_raw_code = sample.code
        sample_code_list = [sub_flow.code for sub_flow in sample.control_flow.subnode]
        sample_code = '<?php\n'
        for i, c in enumerate(sample_code_list):
            if '//sink point:' in c and CWE == '89':
                tem_code_list = c.split('\n')
                tem_code = ""
                for line in tem_code_list:
                    if '//sink point:' in line:
                        tem_code += line[:line.find('= ') + 2] + '"SELECT ".' + line[line.find('= ') + 2:line.find(
                            '//sink point:')] + '\n'
                    else:
                        tem_code += line + '\n'
                sample_code_list[i] = tem_code
                sample_code += tem_code
            else:
                tem_code_list = c.split('\n')
                tem_code = ""
                for line in tem_code_list:
                    if '//sink point:' in line:
                        tem_code += line[:line.find('//sink point:')] + '\n'
                    else:
                        tem_code += line + '\n'
                sample_code_list[i] = tem_code
                sample_code += tem_code
                sample_code += c + '\n'

        direct_input = []
        tmp_path = str(os.path.join(str(synthesis_tmp_path), sample.file))



        # 8 threading
        logger.setLevel(logging.ERROR)
        step = int(len(clear_target_func.function_list) / 8) + 1
        split_lists = [clear_target_func.function_list[i:i + step] for i in
                       range(0, len(clear_target_func.function_list), step)]
        threading_list = []
        for i, function_list in enumerate(split_lists[:1]):
            t = threading.Thread(target=synthesis_threading,
                                 args=[function_list, special_rules, sample, sample_code, sample_code_list,
                                       insert_count, tmp_path, i])
            threading_list.append(t)
            t.start()
        for t in threading_list:
            t.join()
        logger.setLevel(logging.DEBUG)

        # remove similar snippet
        unique_samples = remove_similar_slice(direct_input, [{'slice': sample_code}], threshold=0.85)
        systhesis_sample_lists.append(unique_samples[1:])

    collect_synthesis_samples(systhesis_sample_lists, synthesis_save_path, CWE)


def collect_synthesis_samples(systhesis_sample_lists, synthesis_save_path, CWE):
    synthesis_set = []

    logger.info('[SYNTHESIS] processing synthesis samples...')
    for step, json_data in enumerate(tqdm(systhesis_sample_lists)):


        for i, slice in enumerate(json_data):
            json_data[i]['id'] = i + 1

            code = slice['slice']
            for var in INPUT_VARIABLES:
                if var == '$_GET':
                    continue

                if var in code:
                    code = code.replace(var, '$_GET')

            code = clear_slice(code)
            json_data[i]['slice'] = code

        # process data
        if CWE == '79':
            json_data = rename_all_var_and_str_79(json_data, twice=True)
        elif CWE == '89':
            json_data = rename_all_var_and_str_89(json_data, twice=True)
        json_data = remove_similar_slice(json_data, key='renamed_slice',
                                         compare_label=True, threshold=0.95)
        synthesis_set += json_data

    # remove similar snippet from same clear target
    data_list = {}
    for sample in synthesis_set:
        CVE_database_id = sample['CVE_database_id']
        if str(CVE_database_id) not in data_list.keys():
            data_list[str(CVE_database_id)] = []
        data_list[str(CVE_database_id)].append(sample)

    output_synthesis_set = []
    for step, key in enumerate(tqdm(data_list)):
        project = data_list[key]

        unique_samples = remove_similar_slice(project, key='renamed_slice',
                                              compare_label=True, threshold=0.95)
        output_synthesis_set += unique_samples

    for i, slice in enumerate(output_synthesis_set):
        output_synthesis_set[i]['id'] = i + 1

    write_json(output_synthesis_set, synthesis_save_path)


if __name__ == '__main__':
    log(logging.DEBUG)

    # raw data
    # mode = 'synthesis'
    # CWE = '89'
    #
    # # sample data
    # sample_directory = TMP_PATH + '\\source_code\\'
    # SARD_data_path = DATA_PATH + '\\SARD_php_vulnerability_' + CWE + '.json'
    # crossvul_data_path = DATA_PATH + '\\dataset_unique_' + CWE + '.json'
    #
    # clear_target_directory = DATA_PATH + "\\crossvul\\all"
    #
    #
    # synthesis(sample_directory, clear_target_directory, CWE=CWE, insert_count=8)

    # raw data
    mode = 'synthesis'
    CWE = '79'

    # sample data
    SARD_data_path = DATA_PATH + '\\SARD_php_vulnerability_' + CWE + '.json'
    crossvul_data_path = DATA_PATH + '\\dataset_unique_' + CWE + '.json'

    clear_target_directory = DATA_PATH + "\\crossvul\\all"

    synthesis(SARD_data_path, crossvul_data_path, clear_target_directory, CWE=CWE, insert_count=4)
