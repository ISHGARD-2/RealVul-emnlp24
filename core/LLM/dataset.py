import json
import random
import logging
from tqdm import tqdm
import torch
from torch.utils.data import DataLoader, Dataset
import sys
import datasets
import csv
from utils.func_json import read_json, write_json, json_to_csv
from random import shuffle
from transformers import AutoTokenizer
from configs.settings import LLM_ENV_PATH

MAX_INPUT_LEN = 1024

logger = logging.getLogger(__name__)


class TextDataset(Dataset):
    def __init__(self, file_path, tokenizer, file_type="train", train_type="supervised"):
        self.examples = []
        self.label = []
        self.tokens = []

        data = read_json(LLM_ENV_PATH + file_path)

        code_too_long_count = 0
        for i in tqdm(range(len(data))):
            inputs, labels = generate_and_tokenize_prompt(data[i], tokenizer, file_type, train_type)
            if labels == 'vulnerable':
                label = 1
            else:
                label = 0
            if inputs:
                if file_type == "eval":
                    self.tokens.append(inputs)
                else:
                    newset = {"input_ids": inputs, "labels": [label]}
                    self.examples.append(newset)
                self.label.append({"labels": labels})
            else:
                code_too_long_count += 1
        logger.warning("num of input code out of range(1024): {}".format(str(code_too_long_count)))

        if file_type == "train":
            for example in self.examples[:2]:
                logger.info("*** Example ***")
                # logger.info("input_tokens: {}".format([x.replace('\u0120', '_') for x in example.input_tokens]))
                # logger.info("input_ids: {}".format(' '.join(map(str, example.input_ids))))

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, i):
        return self.examples[i]


def tokenize(prompt, tokenizer):
    result = tokenizer(
        prompt,
        truncation=True,
        max_length=MAX_INPUT_LEN,
        padding=False,
        return_tensors=None,
    )
    return result


def get_code(code, tokenizer, train_type):
    max_input_len = 1024
    tokenize_code = tokenize(code, tokenizer)["input_ids"]
    leng = len(tokenize_code)
    # len1 = tokenize_code.shape[1]
    code_too_long_count = 0

    if train_type == "supervised":
        max_input_len = MAX_INPUT_LEN
    elif train_type == "self-supervised":
        max_input_len = MAX_INPUT_LEN - 128

    if leng >= max_input_len:
        return ''
    return code


def generate_and_tokenize_prompt(data_point, tokenizer, file_type, train_type="supervised"):
    code = get_code(data_point["func"], tokenizer, train_type)
    if code == '':
        return None, None

    resp = data_point["target"]
    if file_type == "eval":
        resp = ""

    if train_type == "supervised":
        full_prompt = \
            f"""{code}"""
    elif train_type == "self-supervised":
        full_prompt = \
            f"""### Instruction: You are a powerful Vulnerability Detection model. Your job is to find whether there is a vulnerability in the code. The Input is some code.The response is secure or vulnerable.
        ### Input:{code}
        ### Response:{resp}"""
    if file_type == "eval":
        return full_prompt, data_point["target"]

    tokenized_prompt = tokenize(full_prompt, tokenizer)
    return tokenized_prompt["input_ids"], resp


def processing_data(data):
    """
    change target label as words vulnerable/secure
    :param data:
    :return:
    """
    list = []

    for one in data:
        newone = {}
        newone["func"] = one["func"]

        if one["target"] == 1:
            newone["target"] = 'vulnerable'
        else:
            newone["target"] = 'secure'

        list.append(newone)
    return list


def generate_jsondata(dataset_path, train_size=0.9, test_size=0.05, random_seed=123):
    """
    split origin dataset into train, test, eval 3 parts
    save into json file
    """
    data = read_json(LLM_ENV_PATH + dataset_path)
    data = processing_data(data)

    random.seed(random_seed)
    random.shuffle(data)
    leng = len(data)
    pos1, pos2 = int(len(data) * train_size), int(len(data) * test_size)

    write_json(data[:pos1], LLM_ENV_PATH + dataset_path + '_train')
    write_json(data[pos1: pos1 + pos2], LLM_ENV_PATH + dataset_path + '_test')
    write_json(data[pos1 + pos2:], LLM_ENV_PATH + dataset_path + '_eval')











# ---------------------------------------------------------------------



class TextClassificationDataset(Dataset):
    def __init__(self, input_ids, attention_mask, labels ):
        self.input_ids = input_ids
        self.attention_mask = attention_mask
        self.labels = labels

    def __len__(self):
        return len(self.input_ids)

    def __getitem__(self, idx):
        return {
            'input_ids': self.input_ids[idx],
            'attention_mask': self.attention_mask[idx],
            'labels': self.labels[idx],

        }


def get_data(input_data):
    shuffle(input_data)
    new_dic = {"text": [i[0] for i in input_data], "labels": [i[1] for i in input_data]}

    for slice in input_data:
        new_dic['text'].append(slice[0])
        label = slice[1]
        label_int = -1
        if label == 'good':
            label_int = 0
        elif label == 'bad':
            label_int = 1
        else:
            logger.error("error label: {}".format(label))
            exit()
        new_dic['labels'].append(label_int)

    data0 = datasets.Dataset.from_dict(new_dic)
    return data0


def get_tokenizer(model_name):
    # Load LLaMA tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    tokenizer.padding_side = "left"
    return tokenizer

def prepare_obj(tokenizer, dataset):
    inputs = tokenizer([i for i in dataset["text"]], padding=True, truncation=True, return_tensors="pt")
    labels = torch.tensor(dataset['labels'])
    text_obj = TextClassificationDataset(input_ids =inputs['input_ids'],attention_mask= inputs['attention_mask'],labels=labels )

    return text_obj


if __name__ == '__main__':
    dataset_path = 'devign.json'
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(name)s -   %(message)s', datefmt='%m/%d/%Y %H:%M:%S',
                        level=logging.INFO)
    # generate_jsondata(dataset_path)

    input_dir = '/home/dcao/code/Python/LLM/CodeLlama/codellama-instruct-13b/dataset/devign.json_eval.json'
    output_dir = '/home/dcao/code/Python/LLM/CodeLlama/codellama-instruct-13b/dataset/devign.json_eval.csv'
    json_to_csv(input_dir, output_dir)
