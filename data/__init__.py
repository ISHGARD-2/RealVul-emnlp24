from configs.const import SYNTHESIS_LEN
from utils.func_json import read_json

if __name__ == '__main__':
    leng = SYNTHESIS_LEN['89']
    json_data = read_json(r"D:\USTC_CD\PROGRAM\LLMforSAST\code\LLMforSAST\data\dataset_unique_89.json")
    count = 0
    for slice in json_data:
        if len(slice['renamed_slice']) <= leng:
            count += 1
    print(count)