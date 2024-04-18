import json

from configs.const import INPUT_VARIABLES
from configs.settings import DATA_PATH


def save_sample_to_file():
    fp = open(DATA_PATH + '\\CVI_10001\\dataset_raw4.json', 'r')
    json_data = json.load(fp)
    fp.close()


    for slice in json_data:
        raw_file_name = slice['file_name']
        raw_id = slice['id']
        raw_code = slice['slice']

        fphp = open(DATA_PATH + '\\CVI_10001\\raw4\\'+raw_file_name[:-4]+'__'+str(raw_id)+'.php', 'w')
        fphp.write(raw_code)
        fphp.close()

def edit_sample_id():
    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out4.json', 'r')
    json_data = json.load(fp)
    fp.close()

    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out4.json', 'w')

    for i, slice in enumerate(json_data):
        json_data[i]['id'] = i+1

    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()

def rename_input_vars():
    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out4.json', 'r')
    json_data = json.load(fp)
    fp.close()

    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out4.json', 'w')

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


if __name__ == '__main__':
    rename_input_vars()