import operator
import logging
import random

import torch
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset
import datasets

from configs.const import SYNTHESIS_LEN
from utils.func_json import read_json
from random import shuffle
from transformers import AutoTokenizer

from utils.log import logger
from utils.my_utils import analy_metadata

MAX_INPUT_LEN = 1024



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


def get_code(pcode, tokenizer, train_const):
    max_input_len = train_const.max_seq_length - 128
    tokenized_pcode = tokenizer(pcode,
                                return_tensors='pt',
                                max_length = max_input_len,
                                truncation=True).input_ids

    if tokenized_pcode.shape[1] >= max_input_len: # too long
        pcode = tokenizer.batch_decode(tokenized_pcode)[0].replace("</s>", '') + "\n....."
        pcode = pcode[pcode.find('<?php'):]
    return pcode



def get_tokenized_dataset(data, tokenizer, train_const, text_str="renamed_slice", label_str="label", predict=False):
    new_dic = {"text": [], "labels": [], "file_name": []}

    for slice in data:
        new_dic['text'].append(slice[text_str])
        new_dic['file_name'].append(slice['file_name'])

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
        max_length=train_const.max_seq_length
    )
    labels = torch.tensor(dataset['labels'])
    dataset = TextClassificationDataset(input_ids=inputs['input_ids'], attention_mask=inputs['attention_mask'],
                                        labels=labels, raw_data=data)

    return dataset



def get_crossvul_data(train_const,
                      crossvul_path,
                      synthesis_data_path,
                      base_model_path,
                      train_mode,
                      train_task,
                      CWE,
                      rate=0.10,
                      predict=False
                      ):
    """
    train_task:
        seq_cls
        causal LM
    train_mode:
        random
        unseen
        random_without_slice
        unseen_without_slice
        random_without_preprocess
        unseen_without_preprocess
    """

    crossvul_data = read_json(crossvul_path)
    synthesis_data = read_json(synthesis_data_path)
    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(
        base_model_path,
        trust_remote_code=True,
    )

    if predict:
        pred_dataset = get_tokenized_dataset(crossvul_data, tokenizer, train_const, text_str="renamed_slice", predict=predict)
        return  pred_dataset


    if CWE == '79':
        project_data = analy_metadata([CWE])
    elif CWE == '89':
        if train_mode == 'unseen_without_slice':
            project_data = analy_metadata([CWE])
        else:
            project_data = analy_metadata([CWE, '79'])

    if train_mode == 'random' or train_mode == 'random_without_preprocess':
        test_data = crossvul_data

        train_data, eval_data = train_test_split(synthesis_data, test_size=rate, random_state=1)

    elif train_mode == 'unseen' or train_mode == 'unseen_without_preprocess':
        train_data, eval_data, test_data = [], [], []

        if CWE == '79':
            test_data_len = len(crossvul_data) * 0.2
        elif CWE == '89':
            test_data_len = len(crossvul_data) * 0.4
            # choose Samples not used for synthesis
            for sample in crossvul_data:
                if len(sample['renamed_slice']) <= SYNTHESIS_LEN[CWE]:
                    test_data.append(sample)

        left_project = []
        left_cve = []
        tmp_cve_list = []
        for proj in project_data:
            if len(test_data) < test_data_len:
                tmp_cve_list += proj['cve']
                for sample in crossvul_data:
                    if sample['CVE_database_id'] in proj['cve']:
                        test_data.append(sample)
            else:
                left_project.append(proj)
                left_cve += proj['cve']

        new_synthesis_data = []
        for sample in synthesis_data:
            if sample['CVE_database_id'] in left_cve:
                new_synthesis_data.append(sample)

        eval_data_len = len(new_synthesis_data) * rate * 0.2
        tmp_cve_list_2 = []
        for i, proj in enumerate(left_project):
            if len(eval_data) < eval_data_len:
                tmp_cve_list_2 += proj['cve']

                if i < len(left_project) * 0.3 * rate:
                    continue

                eval_data = []
                for sample in new_synthesis_data:
                    if sample['raw_sample_id'] in tmp_cve_list_2:
                        if CWE == '79' and sample['CVE_database_id'] in tmp_cve_list_2:
                            eval_data.append(sample)
                        elif CWE == '89':
                            eval_data.append(sample)
            else:
                tmp_cve_list += tmp_cve_list_2

                for sample in new_synthesis_data:
                    if sample['raw_sample_id'] not in tmp_cve_list:
                        train_data.append(sample)
                break

    elif train_mode == 'random_without_slice':
        for i, sample in enumerate(crossvul_data):
            crossvul_data[i]['func'] = get_code(sample['func'], tokenizer, train_const)

        train_data, tmp_data = train_test_split(crossvul_data, test_size=rate, random_state=1)
        eval_data, test_data = train_test_split(tmp_data, test_size=0.5, random_state=1)

        if CWE == '89':
            eval_data, test_data = train_data[:int(len(train_data)*0.1)], eval_data+test_data

    elif train_mode == 'unseen_without_slice':
        for i, sample in enumerate(crossvul_data):
            crossvul_data[i]['func'] = get_code(sample['func'], tokenizer, train_const)


        test_eval_data_len = len(crossvul_data) * rate * 0.5
        train_data, eval_data, test_data = [], [], []

        for proj in project_data:
            if len(test_data) < test_eval_data_len :
                for sample in crossvul_data:
                    if sample['CVE_database_id'] in proj['cve']:
                        test_data.append(sample)
            elif len(eval_data) < test_eval_data_len:
                for sample in crossvul_data:
                    if sample['CVE_database_id'] in proj['cve']:
                        eval_data.append(sample)
            else:
                for sample in crossvul_data:
                    if sample['CVE_database_id'] in proj['cve']:
                        train_data.append(sample)
        if CWE == '89':
            eval_data, test_data = train_data[:int(len(train_data)*0.1)], eval_data+test_data
            bad_sum = sum(data['label'] == "bad" for data in test_data)
            bad_sum = int(bad_sum/2)

            new_test_data = []
            for sample in test_data:
                if sample['label'] == 'bad' and bad_sum >0 :
                    bad_sum -= 1
                    continue
                new_test_data.append(sample)

            test_data = new_test_data

    else:
        raise Exception


    logger.info("[LLM] Dataset info: \ntrainset: {train}\n"
                "evalset: {val}\n"
                "testset: {test}\n".format(
        train=len(train_data),
        val=len(eval_data),
        test=len(test_data)
    ))

    shuffle(train_data)
    shuffle(eval_data)
    shuffle(test_data)

    # setting
    if train_const.set_eos:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"


    logger.info("[LLM] tokenizer initialized ...")
    if 'without_slice' in train_mode:
        text_key = "func"
    elif 'without_preprocess' in train_mode:
        text_key = "slice"
    else:
        text_key = "renamed_slice"

    train_dataset = get_tokenized_dataset(train_data, tokenizer, train_const, text_str=text_key)
    eval_dataset = get_tokenized_dataset(eval_data, tokenizer, train_const, text_str=text_key)
    test_dataset = get_tokenized_dataset(test_data, tokenizer, train_const, text_str=text_key)

    return train_dataset, eval_dataset, test_dataset, tokenizer
