import json
import operator
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


def get_tokenized_dataset(data, tokenizer, text_str="renamed_slice", label_str="label"):
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


# def get_data(data_path, base_model_path):
#     data = read_json(data_path)
#     shuffle(data)
#
#     dis = int(len(data) / 8) * 7
#     train_data, test_data = data[:dis], data[dis:]
#
#     # Load LLaMA tokenizer
#     tokenizer = AutoTokenizer.from_pretrained(
#         base_model_path,
#         trust_remote_code=True,
#
#     )
#     tokenizer.add_special_tokens({'pad_token': '[PAD]'})
#     tokenizer.pad_token = tokenizer.eos_token
#     tokenizer.padding_side = "right"
#
#     train_dataset = get_tokenized_dataset(train_data, tokenizer)
#     test_dataset = get_tokenized_dataset(test_data, tokenizer)
#
#     # train_t = train_dataset.input_ids.tolist()
#     # test_t = test_dataset.input_ids.tolist()
#     return train_dataset, test_dataset, tokenizer


def trans_crossvul_label(crossvul_data, rate):
    corvul_len = len(crossvul_data)
    train_len = int(corvul_len * (1-rate))

    crossvul_data = sorted(crossvul_data, key=operator.itemgetter('project_id'))

    output_train_data = []
    output_test_data = []
    save_train_data = True
    last_project_id = -1

    info = {'train_bad':0, 'train_good':0, 'test_bad':0, 'test_good':0}
    for i in range(len(crossvul_data)):
        sample = crossvul_data[i]
        project_id = sample['project_id']

        if i>train_len and last_project_id !=  project_id:
            save_train_data = False

        if save_train_data:
            if crossvul_data[i]['label'] == 'vulnerable':
                slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'bad', 'file_name':crossvul_data[i]['file_name']}
                output_train_data.append(slice)
                info['train_bad'] += 1

            else:
                slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'good', 'file_name':crossvul_data[i]['file_name']}
                output_train_data.append(slice)
                info['train_good'] += 1
            last_project_id = project_id
        else:
            if crossvul_data[i]['label'] == 'vulnerable':
                slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'bad', 'file_name':crossvul_data[i]['file_name']}
                output_test_data.append(slice)
                info['test_bad'] += 1

            else:
                slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'good', 'file_name':crossvul_data[i]['file_name']}
                output_test_data.append(slice)
                info['test_good'] += 1


    return output_train_data, output_test_data


def get_crossvul_data(crossvul_path, base_model_path, rate = 0.15, SARD_data_path = '', synthesis_data_path=''):

    crossvul_data = read_json(crossvul_path)

    if synthesis_data_path != '':
        synthesis_data = read_json(synthesis_data_path)
        crossvul_data += synthesis_data

    crossvul_train_data, crossvul_test_data = trans_crossvul_label(crossvul_data, rate)

    train_data, test_data = crossvul_train_data, crossvul_test_data
    if SARD_data_path != '':
        data = read_json(SARD_data_path)
        train_data, test_data = data + train_data, test_data

    shuffle(train_data)
    shuffle(test_data)

    test_data = test_data[:500]
    # Load LLaMA tokenizer
    tokenizer = AutoTokenizer.from_pretrained(
        base_model_path,
        trust_remote_code=True,
    )
    tokenizer.add_special_tokens({'pad_token': '[PAD]'})
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    logger.info("[LLM] tokenizer initialized ...")
    train_dataset = get_tokenized_dataset(train_data, tokenizer)
    test_dataset = get_tokenized_dataset(test_data, tokenizer)

    # train_t = train_dataset.input_ids.tolist()
    # test_t = test_dataset.input_ids.tolist()
    return train_dataset, test_dataset, tokenizer
