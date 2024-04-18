import json

from configs.const import INPUT_VARIABLES
from configs.settings import DATA_PATH


def delete_useless_sample():
    fp = open(DATA_PATH + '\\SARD\\SARD_php_vulnerability.json', 'r')
    json_data = json.load(fp)
    fp.close()

    fp = open(DATA_PATH + '\\SARD\\SARD_php_vulnerability.json', 'w')

    count = 1
    output_data = []
    for i, slice in enumerate(json_data):
        code = slice['renamed_code']

        append = False
        for var in INPUT_VARIABLES:
            if var in code:
                append = True
                break

        if append:
            slice['id'] = count
            count += 1
            output_data.append(slice)

    output_data = json.dumps(output_data)
    fp.write(output_data)
    fp.close()

def rename_input_vars():
    fp = open(DATA_PATH + '\\SARD\\SARD_php_vulnerability.json', 'r')
    json_data = json.load(fp)
    fp.close()

    fp = open(DATA_PATH + '\\SARD\\SARD_php_vulnerability.json', 'w')

    for i, slice in enumerate(json_data):
        code = slice['renamed_code']
        for var in INPUT_VARIABLES:
            if var == '$_GET':
                continue

            if var in code:
                code = code.replace(var, '$_GET')

        json_data[i]['renamed_code'] = code


    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()

def add_comment():
    fp = open(DATA_PATH + '\\SARD\\SARD_php_vulnerability.json', 'r')
    json_data = json.load(fp)
    fp.close()

    fp = open(DATA_PATH + '\\SARD\\SARD_php_vulnerability.json', 'w')

    for i, slice in enumerate(json_data):
        code = slice['renamed_code']
        for var in INPUT_VARIABLES:
            if var == '$_GET':
                continue

            if var in code:
                code = code.replace(var, '$_GET')

        json_data[i]['renamed_code'] = code

    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()


if __name__ == '__main__':
    rename_input_vars()