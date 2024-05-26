import os

from utils.func_json import read_json


def rename_file():
    dirPath = r'D:\USTC_CD\PROGRAM\LLMforSAST\code\LLMforSAST\data\crossvul\sqli\\'
    file_list = os.listdir(dirPath)

    for file in file_list:
        file_path = dirPath+file
        if os.path.isfile(file_path) and not file.endswith('.php') and not file.endswith('.py'):
            try:
                new_file_name = file+'.php'
                new_file_path = dirPath+new_file_name
                os.rename(file_path, new_file_path)

            except FileNotFoundError:
                print(f"File {file} does not exist.")
            except PermissionError:
                print(f"Permission denied. Make sure you have access to {file}.")
            except Exception as e:
                print(f"An error occurred: {e}")


def remove_file():
    dirPath = r'D:\USTC_CD\PROGRAM\LLMforSAST\code\LLMforSAST\data\crossvul\sqli\\'
    file_list = os.listdir(dirPath)

    for file in file_list:
        file_path = dirPath+file
        if os.path.isfile(file_path) and file.endswith('.php'):
            fopen = open(file_path, 'r', encoding='utf-8')

            code = fopen.read()
            if code == "404: Not Found":
                fopen.close()
                os.remove(file_path)
                print(f"File {file_path} remove.")
            else:
                fopen.close()

def analy_meta_data(json_data):
    out = {}
    for i, cve in enumerate(json_data):
        if cve['cwe'] != 'CWE-79':
            continue
        cve['id'] = i

        project = '_'.join(cve['url'].split('/')[3:5])
        if project in out.keys():
            out[project].append(cve)
        else:
            out[project] = [cve]

    for key in out.keys():
        if len(out[key])>1:
            continue
    return

if __name__ == "__main__":
    # rename_file()
    # remove_file()

    json_data = read_json(r"D:\USTC_CD\PROGRAM\LLMforSAST\code\LLMforSAST\data\crossvul\metadata.json")
    analy_meta_data(json_data)
