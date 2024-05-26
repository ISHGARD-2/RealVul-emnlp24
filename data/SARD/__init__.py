import codecs
import csv
import json
import logging
import os.path

import chardet
from tqdm import tqdm

from configs.const import SYNTHESIS_LEN
from configs.settings import DATA_PATH
from utils.file import check_comment, clear_slice
from utils.func_json import read_json
from utils.log import log, logger


# def csv_to_json():
#     # 输入文件名和输出文件名
#     csv_file = 'SARD2.csv'
#     json_file = 'SARD2.json'
#
#     # 编码检测
#     # ff = open(file_path, 'rb+')
#     # lines = ff.readline()
#     # file_code = chardet.detect(lines)['encoding']
#     # print(file_code)
#     # ff.close()
#     with open(csv_file, 'r', encoding='utf-8-sig') as file:
#         # 读取 CSV 文件
#         csv_reader = csv.DictReader(file)
#
#         # 将 CSV 数据转换为 JSON 格式
#         json_data = json.dumps(list(csv_reader), ensure_ascii=False, indent=4)
#
#     # 将 JSON 数据写入到文件中
#     with open(json_file, 'w', encoding='utf-8') as file:
#         file.write(json_data)


def collect_SARD(target_CWE='CWE-79'):
    dirPath = './php-vulnerability/'
    file_list = os.listdir(dirPath)

    json_data = {}

    id = 0
    for i in tqdm(range(len(file_list))):
        file = file_list[i]
        json_sample = {}

        file_path = dirPath + file + '/src/'
        manifest_path = dirPath + file + '/manifest.sarif'

        if os.path.isdir(file_path):
            file_id = int(file.split('-')[0])
            php_file_list = os.listdir(file_path)

            if len(php_file_list) == 1:
                php_file_path = file_path + php_file_list[0]
                php_file_name = php_file_list[0]
            else:
                print("two or more php files in one path")
                continue

            if os.path.isfile(php_file_path) and php_file_path.endswith('.php'):
                if not os.path.isfile(manifest_path):
                    print("manifest_path error")
                    continue
                CWE = 'CWE-' + php_file_name.split('_')[1]

                phpfile = codecs.open(php_file_path, "r", encoding='utf-8', errors='ignore')
                php_code = check_comment(phpfile.read(), check_inner_content=False)
                php_code = clear_slice(php_code)

                manifest = open(manifest_path, 'r').read()
                p = manifest.find("\"state\": \"") + 10
                state = manifest[p:p + 4]
                if state.startswith('bad'):
                    state = 'bad'
                elif state.startswith('good'):
                    state = 'good'
                else:
                    raise Exception

                if not 'class ' in php_code:
                    if CWE not in json_data.keys():
                        json_data[CWE] = []

                    id += 1
                    json_sample['id'] = id
                    json_sample['file_id'] = file_id
                    json_sample['label'] = state
                    json_sample['slice'] = php_code
                    json_sample['file_name'] = php_file_name
                    json_sample['CWE'] = CWE
                    json_sample['renamed_slice'] = ''

                    json_data[CWE].append(json_sample)

    for key in json_data.keys():
        cwe_files = json_data[key]
        bad_count = 0
        good_count = 0
        for file in cwe_files:
            if file['label'] == 'good':
                good_count += 1
            else:
                bad_count += 1
        logger.debug("\nCWE: {cwe}\t total: {total}\t bad: {bad}\t good: {good}".format(
            cwe=key, total=bad_count + good_count, bad=bad_count, good=good_count))

        if bad_count + good_count > 2000:
            json_file = DATA_PATH + '\\SARD\\php-vulnerability\\SARD_php_vulnerability' + target_CWE.split('-')[1] + '.json'
            with open(json_file, 'w', encoding='utf-8') as file:
                file.write(json_data)

    json_data = json.dumps(json_data)

    # 将 JSON 数据写入到文件中
    json_file = DATA_PATH + '\\SARD\\php-vulnerability\\SARD_php_vulnerability_all.json'
    with open(json_file, 'w', encoding='utf-8') as file:
        file.write(json_data)


if __name__ == '__main__':
    # log(logging.DEBUG)
    collect_SARD()

