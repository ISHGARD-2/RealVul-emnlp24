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
import train_const as my_c

MAX_INPUT_LEN = 1024

logger = logging.getLogger(__name__)


class TextClassificationDataset(Dataset):
    def __init__(self, input_ids, attention_mask, labels, raw_data=None):
        self.input_ids = input_ids
        self.attention_mask = attention_mask
        self.labels = labels
        self.raw_data = raw_data

    def __len__(self):
        return len(self.input_ids)

    def __getitem__(self, idx):
        return {
            'input_ids': self.input_ids[idx],
            'attention_mask': self.attention_mask[idx],
            'labels': self.labels[idx],

        }


def get_tokenized_dataset(data, tokenizer, text_str="renamed_code", label_str="state"):
    new_dic = {"text": [], "labels": []}

    for slice in data:
        new_dic['text'].append(slice[text_str])
        label = slice[label_str]
        label_int = -1
        if label == 'good':
            label_int = 0
        elif label == 'bad':
            label_int = 1
        else:
            logger.error("error label: {}".format(label))
            exit()
        new_dic['labels'].append(label_int)

    dataset = datasets.Dataset.from_dict(new_dic)

    inputs = tokenizer(
        [i for i in dataset["text"]],
        padding=True,
        truncation=True,
        return_tensors="pt",
        max_length=my_c.max_seq_length
    )
    labels = torch.tensor(dataset['labels'])
    dataset = TextClassificationDataset(input_ids=inputs['input_ids'], attention_mask=inputs['attention_mask'],
                                        labels=labels, raw_data=new_dic)

    return dataset


def get_data(data_path, base_model_path):
    data = read_json(data_path)
    shuffle(data)

    dis = int(len(data) / 8) * 7
    train_data, test_data = data[:dis], data[dis:]

    # Load LLaMA tokenizer
    tokenizer = AutoTokenizer.from_pretrained(
        base_model_path,
        trust_remote_code=True,

    )
    tokenizer.add_special_tokens({'pad_token': '[PAD]'})
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    train_dataset = get_tokenized_dataset(train_data, tokenizer)
    test_dataset = get_tokenized_dataset(test_data, tokenizer)

    # train_t = train_dataset.input_ids.tolist()
    # test_t = test_dataset.input_ids.tolist()
    return train_dataset, test_dataset, tokenizer


def trans_crossvul_label(crossvul_data):
    output_data = []
    for i in range(len(crossvul_data)):
        if crossvul_data[i]['label'] == 'vulnerable':
            slice = {'renamed_code':crossvul_data[i]['slice'], "state":'bad'}
            output_data.append(slice)

        else:
            slice = {'renamed_code': crossvul_data[i]['slice'], "state": 'good'}
            output_data.append(slice)

    return output_data


def get_crossvul_data(data_path, crossvul_path, base_model_path, crossvul_path2=''):
    data = read_json(data_path)
    crossvul_data = read_json(crossvul_path)
    crossvul_data = trans_crossvul_label(crossvul_data)

    if crossvul_path2 != '':
        data += crossvul_data

        crossvul_data = read_json(crossvul_path2)
        crossvul_data = trans_crossvul_label(crossvul_data)
        shuffle(crossvul_data)

    train_data, test_data = data, crossvul_data
    shuffle(train_data)
    shuffle(test_data)

    # Load LLaMA tokenizer
    tokenizer = AutoTokenizer.from_pretrained(
        base_model_path,
        trust_remote_code=True,

    )
    tokenizer.add_special_tokens({'pad_token': '[PAD]'})
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    train_dataset = get_tokenized_dataset(train_data, tokenizer)
    test_dataset = get_tokenized_dataset(test_data, tokenizer)

    # train_t = train_dataset.input_ids.tolist()
    # test_t = test_dataset.input_ids.tolist()
    return train_dataset, test_dataset, tokenizer
