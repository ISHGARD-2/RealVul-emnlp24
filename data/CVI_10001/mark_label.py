import json
import threading
import time
from math import ceil
from time import sleep

import copy
import operator


import os

from tqdm import tqdm

from configs.settings import DATA_PATH
from utils.file import check_comment, clear_slice

os.environ["http_proxy"] = 'http://127.0.0.1:10810'
os.environ["https_proxy"] = 'http://127.0.0.1:10810'

import openai
from openai import OpenAI
client = OpenAI(api_key='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')




# 定义调用 ChatGPT 的函数
def Chat_Code(Order, Describe, Model="gpt-3.5-turbo"):
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


def mark_label_Crossvul_sample():
    Describe = """您的身份是精通PHP的漏洞挖掘专家。
请只根据我给出的代码，假设所有用户定义函数都过滤了输入，不考虑上下文。
判断是否一定存在由$_GET输入，并传递到echo输出，导致的XSS漏洞。
请不要考虑是否存在风险，只考虑是否能确定漏洞一定存在。
如果您非常确定此代码中存在XSS漏洞，请返回'vulnerable'；
否则，请返回'safe'。"""

    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out3.json', 'r')
    json_data = json.load(fp)
    fp.close()

    output_json = []

    start_id = 0
    count = len(output_json) + 1

    for i, slice in enumerate(json_data):
        # if i < start_id:
        #     # start from last processed id
        #     continue

        if slice['label'] != '':
            output_json.append(slice)
            continue

        try:
            # print('\n' + slice['slice'].replace('$vulchecker_output = ', 'echo '))
            print('\n-------------------------' + slice['file_name'] + ' ' + str(
                slice['id']) + '----------------------------\n')

            code = slice['renamed_slice']

            label = Chat_Code(code, Describe, Model="gpt-3.5-turbo")

            if label in ['safe', "Safe", "'safe'"]:
                GPT_label = 'safe'
            elif label in ['vulnerable', "Vulnerable", "'vulnerable'"]:
                GPT_label = 'vulnerable'
            else:
                check = input("check:")
                if check != '':
                    if check == '0':
                        GPT_label = 'safe'
                    elif check == '1':
                        GPT_label = 'vulnerable'
                    else:
                        # drop this slice
                        continue

            slice['label'] = GPT_label
            slice['id'] = count
            output_json.append(slice)
            count += 1

            # print(r'code_one_line: {}'.format(code.replace('\n', '\\n')), end='')
            # counter_sample = input("\ncounter_sample: \n")
            # counter_sample = counter_sample.replace('\\n', '\n')
            #
            # if counter_sample != '':
            #     new_slice = copy.deepcopy(slice)
            #     new_slice['slice'] = counter_sample
            #     new_slice['id'] = count
            #
            #     if GPT_label == 'safe':
            #         new_slice['label'] = 'vulnerable'
            #     else:
            #         new_slice['label'] = 'safe'
            #
            #     new_slice['message'] = 'synthesis'
            #     output_json.append(new_slice)
            #     count += 1

            fp = open(DATA_PATH + '\\CVI_10001\\dataset_out3.json', 'w')
            output_data = json.dumps(output_json)
            fp.write(output_data)

        except:
            fp = open(DATA_PATH + '\\CVI_10001\\dataset_out3.json', 'w')
            output_data = json.dumps(output_json)
            fp.write(output_data)
            break
    fp.close()


def mark_label_SARD_sample(slice):
    global thread_slices_receive

    Describe = "Your identity is an expert proficient in PHP. " \
               "Please replace the variable names in the following PHP code with more reasonable names. " \
               "Do not include 'tained' and 'sanitized' in the variable names. " \
               "Please only return PHP code."

    if slice['renamed_code'] != '':
        thread_slices_receive.append(slice)
        return

    try:
        # # print('\n' + slice['slice'].replace('$vulchecker_output = ', 'echo '))
        # print('\n-------------------------' + slice['file_name'] + '----------------------------\n')

        code = slice['code'] + '?>\n'

        renamed_code = Chat_Code(code, Describe)

        renamed_code = check_comment(renamed_code, check_inner_content=False)
        renamed_code = clear_slice(renamed_code)

        if not renamed_code.startswith('<?php'):
            renamed_code = ''

        slice['renamed_code'] = renamed_code
        thread_slices_receive.append(slice)
    except:
        thread_slices_receive.append(slice)

    return


def mark_label_SARD_sample_mthread(cut=8):
    global thread_slices_receive
    fp = open(DATA_PATH + '/SARD/SARD_php_vulnerability.json', 'r')
    json_data = json.load(fp)
    fp.close()

    leng = ceil(len(json_data) / cut)

    for i in tqdm(range(leng)):
        t1 = time.time()
        fp = open(DATA_PATH + '/SARD/SARD_php_vulnerability.json', 'w')

        slices = json_data[i * cut:i * cut + cut]

        threading_list = []
        thread_slices_receive = []
        for l in range(cut):
            t = threading.Thread(target=mark_label_SARD_sample, args=(slices[l],))
            t.start()
            threading_list.append(t)
        for t in threading_list:
            t.join()

        thread_slices_receive = sorted(thread_slices_receive, key=operator.itemgetter('id'))
        for l in range(cut):
            json_data[i * cut + l] = thread_slices_receive[l]

        output_data = json.dumps(json_data)
        fp.write(output_data)
        fp.close()

        t2 = time.time()
        if t2 - t1 < 1.5:
            sleep(1)

    fp.close()


def check_Crossvul_label():
    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out5.json', 'r')
    json_data = json.load(fp)
    fp.close()

    for i, slice in enumerate(json_data):
        # print('\n' + slice['slice'].replace('$vulchecker_output = ', 'echo '))
        print('\n-------------------------' + slice['file_name'] + '----------------------------\n')
        code = slice['slice']
        label = slice['label']

        print(code)
        print('LABEL: ', label)

        check = input("check:")
        if check != '':
            label = check

        json_data[i]['label'] = label

    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out5.json', 'w')
    output_data = json.dumps(json_data)
    fp.write(output_data)
    fp.close()


def add_vulnerable_Crossvul_sample():
    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out4.json', 'r')
    json_data = json.load(fp)
    fp.close()

    start_id = 18
    count = len(json_data) + 1
    output_json = []

    for i, slice in enumerate(json_data):
        output_json.append(slice)
        # print('\n' + slice['slice'].replace('$vulchecker_output = ', 'echo '))
        print('\n-------------------------' + slice['file_name'] + ' ' + str(
            slice['id']) + '----------------------------\n')

        code = slice['slice']
        label = slice['label']

        if label == 'safe':
            print('\n{}\n'.format(code))
            print(r'code_one_line: {}'.format(code.replace('\n', '\\n')), end='')
            counter_sample = input("\ncounter_sample: \n")
            counter_sample = counter_sample.replace('\\n', '\n')

            if counter_sample != '':
                new_slice = copy.deepcopy(slice)
                new_slice['slice'] = counter_sample
                new_slice['id'] = count

                if label == 'safe':
                    new_slice['label'] = 'vulnerable'
                else:
                    new_slice['label'] = 'safe'

                new_slice['message'] = 'synthesis'
                output_json.append(new_slice)
                count += 1

    fp = open(DATA_PATH + '\\CVI_10001\\dataset_out5.json', 'w')
    output_data = json.dumps(output_json)
    fp.write(output_data)


if __name__ == '__main__':

    mark_label_Crossvul_sample()

#     code = """
# def eval_codellama_model(eval_dataset, new_model_path, base_model_path):
#     model = AutoModelForSequenceClassification.from_pretrained(
#     base_model_path,
#     device_map="auto",
#     num_labels=2,
#     torch_dtype=torch.float16)
#     lora_model = PeftModel.from_pretrained(model, new_model_path, torch_dtype=torch.float16)
#     lora_model = lora_model.merge_and_unload()
#     lora_model.eval()
#
#     with torch.no_grad():
#         tr_data = DataLoader(eval_dataset, batch_size=1, shuffle=False)
#         device = torch.device('cuda')
#         for step, batch in enumerate(tqdm(tr_data)):
#             batch = tuple(batch[t].to(device) for t in batch)
#             b_input_ids, b_input_mask, b_labels = batch
#
#             test_output = lora_model(b_input_ids,
#                                      attention_mask=b_input_mask)
#             t = test_output.logits[0].cpu().numpy()
#             eval_predictions = torch.argmax(test_output.logits, dim=1).tolist()[0]
#
#             """
#
#     Describe = "请作为大语言模型的专家，帮我分析这里给出的主要部分的代码是否有问题。" \
#                "这里我加载微调过的codellama模型，并测试其语句分类性能。" \
#                "但是现在在模型加载的部分似乎有问题，模型分类的输出结果基本上都是positive。但是如果我加载这个微调过的模型继续训练，模型似乎能正确加载，分类正确率很高。"
#     try:
#         Chat_Code(code, Describe)
#
#     except:
#         print('failed')
