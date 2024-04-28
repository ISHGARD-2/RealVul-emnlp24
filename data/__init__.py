import os




# def rename_file():
#     dirPath = 'D:\\USTC_CD\\学习\\我的论文\\LLMforSAST\\code\\LLMforSAST\\data\\crossvul\\raw8\\'
#     file_list = os.listdir(dirPath)
#
#     for file in file_list:
#         file_path = dirPath+file
#         if os.path.isfile(file_path) and not file.endswith('.php') and not file.endswith('.py'):
#             try:
#                 new_file_name = file+'.php'
#                 new_file_path = dirPath+new_file_name
#                 os.rename(file, new_file_name)
#
#             except FileNotFoundError:
#                 print(f"File {file} does not exist.")
#             except PermissionError:
#                 print(f"Permission denied. Make sure you have access to {file}.")
#             except Exception as e:
#                 print(f"An error occurred: {e}")
#
#
# def remove_file():
#     dirPath = 'D:\\USTC_CD\\学习\\我的论文\\LLMforSAST\\code\\LLMforSAST\\data\\crossvul\\raw8\\'
#     file_list = os.listdir(dirPath)
#
#     for file in file_list:
#         file_path = dirPath+file
#         if os.path.isfile(file_path) and file.endswith('.php'):
#             fopen = open(file_path, 'r', encoding='utf-8')
#
#             code = fopen.read()
#             if code == "404: Not Found" or len(code) > 30000:
#                 fopen.close()
#                 os.remove(file_path)
#                 print(f"File {file_path} remove.")
#             else:
#                 fopen.close()

if __name__ == "__main__":
    #rename_file()
    print(len("""<?php
// controlable parameters: 
$taint = $_GET['input0'];

// php code: 
	if( $taint['type'] == CUSTOM_FIELD_TYPE_MULTILIST ) {
		echo  helper_get_tab_index() . $taint['id'] . $taint['id'] . _PAD_ ;		//sink point: $taint;
	}

"""))