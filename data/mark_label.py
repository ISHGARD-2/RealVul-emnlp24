import json
from time import sleep

import openai
from openai import OpenAI

import os

os.environ["http_proxy"] = 'http://127.0.0.1:10810'
os.environ["https_proxy"] = 'http://127.0.0.1:10810'
client = OpenAI(api_key='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')
# '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'

Describe = "Your identity is a vulnerability mining expert proficient in PHP. " \
           "You can analyze the PHP code I provide and check for XSS vulnerabilities. " \
           "If there is an XSS vulnerability, just return 'vulnerable'; " \
           "otherwise, reply that it does not 'safe'." \
           "If you are unsure whether the vulnerability exists, return 'unknown'"


# 定义调用 ChatGPT 的函数
def Chat_Code(Order, Model="gpt-4"):
    '''
    Order：告诉 ChatGPT 如何处理数据的命令
    Model：使用的语言模型，默认使用 gpt-3.5-turbo
    '''
    global Space
    global BaseMessage
    global result

    # 定义和储存历史消息
    BaseMessage = [{"role": "system", "content": Describe}]

    # 定义变量 result，用于储存 ChatGPT 返回的代码
    result = ''

    # 定义命名空间，用于储存结果
    Space = {}

    # 以 "user" 的身份向 ChatGPT 提问，内容为输入的 Order
    ##  不满意回答时可以撤回上一步的历史消息
    if Order == "撤回上一步历史消息":
        BaseMessage = BaseMessage[:-2]

        ## 退出时清空命名空间并重置历史消息
    elif Order == "exit":
        Space = {}
        BaseMessage = [{"role": "system", "content": Describe}]
        result = ""
    ## 正常提问
    else:
        Message = {"role": "user", "content": Order}
        ## 将提问内容加入历史消息，实现连续对话功能
        BaseMessage.append(Message)

        # 使用函数 openai.ChatCompletion.create() 得到 ChatGPT 返回的响应信息
        response = client.chat.completions.create(
            model=Model,
            messages=BaseMessage
        )

        # 提取响应中的的代码，存入变量 result
        result = response.choices[0].message.content
        print(Order, '\n')
        print(result)  # 查看 ChatGPT 给出的解决代码
        return result


def mark_label():
    fp = open('D:\\USTC_CD\\学习\我的论文\\LLMforSAST\\code\\LLMforSAST\\data\\CVI_10001\\dataset_raw5.json', 'r')
    json_data = json.load(fp)
    fp.close()

    for i, slice in enumerate(json_data):
        if slice['label'] != '':
            continue

        try:
            # print('\n' + slice['slice'].replace('$vulchecker_output = ', 'echo '))
            print('\n-------------------------' + slice['file_name'] + '----------------------------\n')
            fp = open('D:\\USTC_CD\\学习\我的论文\\LLMforSAST\\code\\LLMforSAST\\data\\CVI_10001\\dataset_out5.json', 'w')

            code = slice['slice']

            label = Chat_Code(code)

            if label in ['safe', "Safe", "'safe'"]:
                GPT_label = 'safe'
                if slice['slice_label'] == 'bad':
                    check = input("check:")
                    if check != '':
                        GPT_label = check
            elif label in ['vulnerable', "Vulnerable", "'vulnerable'"]:
                GPT_label = 'vulnerable'
                if slice['slice_label'] == 'good':
                    check = input("check:")
                    if check != '':
                        GPT_label = check
            elif label in ['unknown', "Unknown", "'unknown"]:
                GPT_label = 'unknown'
                check = input("check:")
                if check != '':
                    GPT_label = check
            else:
                GPT_label = input("input label:")

            json_data[i]['label'] = GPT_label

            output_data = json.dumps(json_data)
            fp.write(output_data)

            sleep(1)
        except:
            output_data = json.dumps(json_data)
            fp.write(output_data)
            break
    fp.close()




if __name__ == '__main__':
    mark_label()

#     code = """<?php
# // controlable parameters:
#
# // php code:
# 		if( !empty($_GET['dir']) ){
# 			echo ' <input type="hidden" name="dir" value="'.htmlspecialchars($_GET['dir']).'" />'		//sink point here.;
# 		}"""
#     Chat_Code(code)
