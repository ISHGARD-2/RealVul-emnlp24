import codecs
import csv
import json
import os.path

import chardet
from tqdm import tqdm

from utils.file import check_comment, clear_slice


def csv_to_json():
    # 输入文件名和输出文件名
    csv_file = 'SARD2.csv'
    json_file = 'SARD2.json'

    # 编码检测
    # ff = open(file_path, 'rb+')
    # lines = ff.readline()
    # file_code = chardet.detect(lines)['encoding']
    # print(file_code)
    # ff.close()
    with open(csv_file, 'r', encoding='utf-8-sig') as file:
        # 读取 CSV 文件
        csv_reader = csv.DictReader(file)

        # 将 CSV 数据转换为 JSON 格式
        json_data = json.dumps(list(csv_reader), ensure_ascii=False, indent=4)

    # 将 JSON 数据写入到文件中
    with open(json_file, 'w', encoding='utf-8') as file:
        file.write(json_data)


def collect_SARD():
    dirPath = './php-vulnerability/'
    file_list = os.listdir(dirPath)

    json_data = []

    id = 0
    for i in tqdm(range(len(file_list))):
        file = file_list[i]
        json_sample = {}

        file_path = dirPath + file+'/src/'
        manifest_path = dirPath + file +'/manifest.sarif'

        if os.path.isdir(file_path):
            file_id = int(file.split('-')[0])
            php_file_list = os.listdir(file_path)

            if len(php_file_list) == 1:
                php_file_path = file_path+php_file_list[0]
                php_file_name = php_file_list[0]
            else:
                print("two or more php files in one path")
                continue

            if os.path.isfile(php_file_path) and php_file_path.endswith('.php'):
                if not os.path.isfile(manifest_path):
                    print("manifest_path error")
                    continue
                CWE = 'CWE-'+php_file_name.split('_')[1]

                phpfile = codecs.open(php_file_path, "r", encoding='utf-8', errors='ignore')
                php_code = check_comment(phpfile.read(), check_inner_content=False)
                php_code = clear_slice(php_code)

                manifest = open(manifest_path, 'r').read()
                p = manifest.find("\"state\": \"")+10
                state = manifest[p:p+4]
                if state.startswith('bad'):
                    state = 'bad'

                if CWE=='CWE-79':
                    if not 'class ' in php_code:
                        id += 1
                        json_sample['id'] = id
                        json_sample['file_id'] = file_id
                        json_sample['state'] = state
                        json_sample['code'] = php_code
                        json_sample['file_name'] = php_file_name
                        json_sample['CWE'] = CWE
                        json_sample['renamed_code'] = ''

                        json_data.append(json_sample)

    json_data = json.dumps(json_data)

    # 将 JSON 数据写入到文件中
    json_file = 'SARD_php_vulnerability.json'
    with open(json_file, 'w', encoding='utf-8') as file:
        file.write(json_data)


collect_SARD()