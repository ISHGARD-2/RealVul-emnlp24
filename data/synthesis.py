import copy
import difflib
import json
import logging
import os
import random
import re
import threading

from tqdm import tqdm

from configs.const import SYNTHESIS_LEN, INPUT_VARIABLES
from configs.settings import DATA_PATH, TMP_PATH
from core import args_prepare, FuncCall, scan
from data.CVI_10001.sample_process import rename_all_var_and_str0
from utils.file import Directory, clear_slice
from utils.log import log, logger

# raw data
mode = 'synthesis'

# sample data
sample_directory = DATA_PATH + '\\source_code\\'
SARD_data_path = DATA_PATH + '/SARD/SARD_php_vulnerability.json'
crossvul_data_path = DATA_PATH + '/CVI_10001/dataset_out_all_unique.json'


def save_sample_to_file(path, directory, source='crossvul'):
    fp = open(path, 'r')
    json_data = json.load(fp)
    fp.close()

    if not os.path.exists(directory):
        os.makedirs(directory)

    for slice in json_data:
        code = slice['renamed_slice']

        if len(code) > SYNTHESIS_LEN:
            continue

        if source == 'crossvul':
            file_name = slice['file_name']
            id = slice['id']
            php_path = directory+source+'_'+file_name[:-4]+'__'+str(id)+'.php'
        elif source == 'SARD':
            file_id = slice['file_id']
            raw_id = slice['id']
            state = slice['label']
            php_path = directory + source+'_'+state+'_'+str(file_id) + '__' + str(raw_id) + '.php'
        else:
            continue

        fphp = open(php_path, 'w')
        fphp.write(code)
        fphp.close()


def remove_similar_slice(json_data, unique_samples=[], threshold=0.8, key='slice', compare_label=False):
    unique_samples = unique_samples
    for i in range(len(json_data)):
        sample = json_data[i][key]
        sample = re.sub('\s|\t|\n','',sample)

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
            if similarity > threshold :
                unique = False
                break
        if unique:
            unique_samples.append(json_data[i])
    return unique_samples



def func_prepare(corssvul_target_directory):


    if len(os.listdir(sample_directory)) == 0:
        save_sample_to_file(SARD_data_path, sample_directory, source='SARD')
        save_sample_to_file(crossvul_data_path, sample_directory, source='crossvul')

    fp = open(crossvul_data_path, 'r')
    json_data = json.load(fp)
    sample_project_list = [slice['project_id'] for slice in json_data]
    fp.close()

    # raw files
    files, file_count, time_consume = Directory(corssvul_target_directory).collect_files()
    new_file_list = []
    for file in files[0][1]['list']:
        project_id = int(file.split('_')[1])
        if project_id not in sample_project_list:
            new_file_list.append(file)
    files[0][1]['list'] = new_file_list

    # raw function list and control flow
    crossvul_func_call = FuncCall(corssvul_target_directory, files)
    crossvul_func_call.main(mode)

    files, file_count, time_consume = Directory(sample_directory).collect_files()
    sample_func_call = FuncCall(sample_directory, files)
    sample_func_call.main(mode)

    return sample_func_call, crossvul_func_call

def synthesis(corssvul_target_directory, insert_count=4, line_count=50):
    sample_func_call, crossvul_func_call = func_prepare(corssvul_target_directory)


    base_tmp_path = TMP_PATH+"\\synthesis\\"+corssvul_target_directory.split('\\')[-1]
    for sample in sample_func_call.function_list:
        logger.info("[synthesis] {}".format(sample.file))

        tmp_path = base_tmp_path+"\\"+ sample.file+"\\"
        if not os.path.exists(tmp_path):
            os.makedirs(tmp_path)

        sample_raw_code = sample.code
        flows_code = [sub_flow.code for sub_flow in sample.control_flow.subnode]
        raw_flow_code = '<?php\n'
        for c in flows_code:
            raw_flow_code += c +'\n'

        for func in crossvul_func_call.function_list:
            func_code = '<?php\n'
            if not hasattr(func, 'control_flow'):
                continue

            if func.func_name != 'root' and func.func_type != None:
                for i, par in enumerate(func.node_ast.params):
                    func_code += par.name + " = $_GET['input0" + str(i) + "'];\n"
            for i, sub_flow in enumerate(func.control_flow.subnode):
                if 'echo ' not in sub_flow.code and func_code.count('\n') <= line_count+10:
                    func_code += clear_slice(sub_flow.code)+'\n'

            func_code_list = func_code.split('\n')

            sample_count = len(flows_code)
            if sample_count > len(func_code_list) - 3 or sample_count>10:
                continue
            max_line=len(func_code_list)-1
            if max_line > line_count:
                max_line = line_count
            for i in range(insert_count):
                tmp_func_code_list = copy.deepcopy(func_code_list)
                insert_pos = random.sample(range(2, max_line), sample_count);
                insert_pos = sorted(insert_pos)
                for l in range(sample_count-1,-1,-1):
                    tmp_func_code_list.insert(insert_pos[l], '\n'+flows_code[l]+'\n')

                final_code = '\n'.join(tmp_func_code_list)
                php_path = tmp_path + func.file+"__"+str(i)+"__"+sample.file+".php"
                fphp = open(php_path, 'w', encoding='utf-8')
                fphp.write(final_code)
                fphp.close()

        files, file_count, time_consume = Directory(tmp_path).collect_files()
        tmp_func_call = FuncCall(tmp_path, files)
        tmp_func_call.main(mode)

        scan(tmp_func_call, target_directory=tmp_path, store_path=base_tmp_path+'\\'+sample.file+'__',special_rules=['CVI_10001.py'], files=tmp_func_call.files,
                            mode=mode)

        json_path = base_tmp_path + '\\' + sample.file + '__CVI_10001_dataset.json'
        fp = open(json_path, 'r')
        json_data = json.load(fp)
        fp.close()
        unique_samples = remove_similar_slice(json_data, [{'slice': raw_flow_code}])
        if len(unique_samples) > 1:
            fp = open(json_path, 'w')
            output_data = json.dumps(unique_samples[1:])
            fp.write(output_data)
            fp.close()

        # remove tmp files
        tmp_file_list = os.listdir(tmp_path)
        for tmp_file in tmp_file_list:
            os.remove(tmp_path+tmp_file)






def collect_synthesis_samples(corssvul_target_directory):
    json_file_list = os.listdir(corssvul_target_directory)

    fp = open(SARD_data_path, 'r')
    SARD_raw_samples = json.load(fp)
    fp.close()
    fp = open(crossvul_data_path, 'r')
    crossvul_raw_samples = json.load(fp)
    fp.close()

    synthesis_set = []

    for step, json_file in enumerate(json_file_list):
        if step % 50 == 0:
            print("[INFO] now json "+corssvul_target_directory.split('\\')[-1]+"\t step: {}".format(str(step)))

        if not json_file.endswith('.json'):
            continue

        # crossvul or sard
        dataset_name = json_file.split('_')[0]

        raw_sample = None
        if dataset_name == 'crossvul':
            # sample info
            sample_id = int(json_file.split('__')[1][:-4])
            sample_file_name = json_file.split('_')[1] +'_'+ json_file.split('_')[2] +'_'+ json_file.split('_')[3] + '.php'

            # find origin sample
            for sam in crossvul_raw_samples:
                if sam['id'] == sample_id:
                    # check_file_name
                    if sample_file_name != sam['file_name']:
                        raise Exception

                    raw_sample = sam
                    break
        else:
            # sample info
            sample_file_id = int(json_file.split('_')[2])
            sample_id = int(json_file.split('__')[1][:-4])
            sample_state = json_file.split('_')[1]

            # find origin sample
            for sam in SARD_raw_samples:
                if sam['id'] == sample_id:
                    # check_file_name
                    if sample_file_id != sam['file_id'] or sample_state != sam['label']:
                        raise Exception

                    raw_sample = sam
                    break

        if raw_sample is None:
            raise Exception

        raw_label = raw_sample['label']
        if raw_label == 'vulnerable':
            raw_label = 'bad'
        elif raw_label == 'safe':
            raw_label = 'good'


        # read_file
        json_file_path = corssvul_target_directory + '\\' + json_file
        fp = open(json_file_path, 'r')
        json_data = json.load(fp)
        fp.close()

        for i, slice in enumerate(json_data):
            json_data[i]['id'] = i + 1
            json_data[i]['project_id'] = int(slice['file_name'].split('\\')[-1].split('_')[1])
            json_data[i]['label'] = raw_label
            json_data[i]['message'] = 'synthesis'

            code = slice['slice']
            for var in INPUT_VARIABLES:
                if var == '$_GET':
                    continue

                if var in code:
                    code = code.replace(var, '$_GET')


            code = clear_slice(code)
            json_data[i]['slice'] = code

        # process data
        json_data = rename_all_var_and_str0(json_data, twice=True)
        json_data = remove_similar_slice(json_data, unique_samples=[], threshold=0.8, key='renamed_slice', compare_label=True)

        synthesis_set += json_data

    data_list = {}
    for sample in synthesis_set:
        project_id = sample['project_id']
        if str(project_id) not in data_list.keys():
            data_list[str(project_id)] = []
        data_list[str(project_id)].append(sample)

    output_synthesis_set = []
    for step, key in enumerate(data_list):
        if step % 10 == 0:
            print("[INFO] now key " + corssvul_target_directory.split('\\')[-1] + "\t step: {}".format(str(step)))
        project = data_list[key]

        unique_samples = remove_similar_slice(project, unique_samples=[], threshold=0.95, key='renamed_slice', compare_label=True)

        output_synthesis_set += unique_samples

    output_synthesis_set_path = corssvul_target_directory+'_synthesis_out.json'
    fp = open(output_synthesis_set_path, 'w')
    output_data = json.dumps(output_synthesis_set)
    fp.write(output_data)
    fp.close()


if __name__=='__main__':
    log(logging.DEBUG)

    raw = [1,2,3,4,5]
    threading_list = []
    final_data=[]
    for i, r in enumerate(raw):
        corssvul_target_directory = r"D:\USTC_CD\PROGRAM\LLMforSAST\code\LLMforSAST\tmp\synthesis\raw" + str(r)
        synthesis_set_path = corssvul_target_directory + '_synthesis_out.json'

        fp = open(synthesis_set_path, 'r')
        final_data += json.load(fp)
        fp.close()


        #collect_synthesis_samples(corssvul_target_directory)
    #     t = threading.Thread(target=collect_synthesis_samples, args=[corssvul_target_directory])
    #     threading_list.append(t)
    #     t.start()
    # for t in threading_list:
    #     t.join()

    for i, slice in enumerate(final_data):
        final_data[i]['id'] = i + 1

    final_path = DATA_PATH + "\\CVI_10001\\dataset_synthesis.json"
    fp = open(final_path, 'w')
    output_data = json.dumps(final_data)
    fp.write(output_data)
    fp.close()
