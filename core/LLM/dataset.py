import operator
import logging
import torch
from torch.utils.data import Dataset
import datasets

from configs.const import SYNTHESIS_LEN
from utils.func_json import read_json
from random import shuffle
from transformers import AutoTokenizer

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


def get_tokenized_dataset(data, tokenizer, train_const, text_str="renamed_slice", label_str="label"):
    new_dic = {"text": [], "labels": [], "file_name":[]}

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


def trans_crossvul_label(crossvul_data, rate, issynthesis=False):

    if issynthesis:
        key_name = 'raw_sample_id'

        crossvul_tmp_data = []
        output_train_data = []
        output_test_data = []

        info = {'train_bad': 0, 'train_good': 0, 'test_bad': 0, 'test_good': 0}


        for i in range(len(crossvul_data)):
            sample = crossvul_data[i]
            key_id = sample[key_name]
            CVE_database_id = sample['CVE_database_id']
            dataset_name = sample['raw_dataset']

            if dataset_name == 'SARD':
                if crossvul_data[i]['label'] == 'vulnerable':
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'bad',
                             'file_name': crossvul_data[i]['file_name']}
                    output_train_data.append(slice)
                    info['train_bad'] += 1

                else:
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'good',
                             'file_name': crossvul_data[i]['file_name']}
                    output_train_data.append(slice)
                    info['train_good'] += 1
            else:
                crossvul_tmp_data.append(sample)

        crossvul_data = sorted(crossvul_tmp_data, key=operator.itemgetter(key_name))
        corvul_len = len(crossvul_data)
        train_len = int(corvul_len * (1 - rate*2))

        CVE_database_id_list = set()
        save_train_data = True
        last_key_id = -1
        for i in range(len(crossvul_data)):
            sample = crossvul_data[i]
            key_id = sample[key_name]
            CVE_database_id = sample['CVE_database_id']

            if save_train_data and i > train_len and last_key_id != key_id:
                save_train_data = False
                CVE_database_id_list = list(CVE_database_id_list)

            if save_train_data and CVE_database_id < 4500:
                if crossvul_data[i]['label'] == 'vulnerable':
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'bad',
                             'file_name': crossvul_data[i]['file_name']}
                    output_train_data.append(slice)
                    info['train_bad'] += 1

                else:
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'good',
                             'file_name': crossvul_data[i]['file_name']}
                    output_train_data.append(slice)
                    info['train_good'] += 1
                CVE_database_id_list.add(CVE_database_id)
                last_key_id = key_id
            elif not save_train_data and CVE_database_id >= 4500:
                if crossvul_data[i]['label'] == 'vulnerable':
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'bad',
                             'file_name': crossvul_data[i]['file_name']}
                    output_test_data.append(slice)
                    info['test_bad'] += 1

                else:
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'good',
                             'file_name': crossvul_data[i]['file_name']}
                    output_test_data.append(slice)
                    info['test_good'] += 1

        return output_train_data, output_test_data

    else:
        corvul_len = len(crossvul_data)
        train_len = int(corvul_len * (1 - rate))
        crossvul_data = sorted(crossvul_data, key=operator.itemgetter('CVE_database_id'))

        output_train_data = []
        output_test_data = []
        save_train_data = True
        last_CVE_database_id = -1

        info = {'train_bad': 0, 'train_good': 0, 'test_bad': 0, 'test_good': 0}
        for i in range(len(crossvul_data)):
            sample = crossvul_data[i]
            CVE_database_id = sample['CVE_database_id']

            if save_train_data and i > train_len and last_CVE_database_id != CVE_database_id:
                save_train_data = False

            if save_train_data:
                if crossvul_data[i]['label'] == 'vulnerable':
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'bad',
                             'file_name': crossvul_data[i]['file_name']}
                    output_train_data.append(slice)
                    info['train_bad'] += 1

                else:
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'good',
                             'file_name': crossvul_data[i]['file_name']}
                    output_train_data.append(slice)
                    info['train_good'] += 1
                last_CVE_database_id = CVE_database_id
            else:
                if crossvul_data[i]['label'] == 'vulnerable':
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'bad',
                             'file_name': crossvul_data[i]['file_name']}
                    output_test_data.append(slice)
                    info['test_bad'] += 1

                else:
                    slice = {'renamed_slice': crossvul_data[i]['renamed_slice'], "label": 'good',
                             'file_name': crossvul_data[i]['file_name']}
                    output_test_data.append(slice)
                    info['test_good'] += 1

        return output_train_data, output_test_data



def get_crossvul_data(train_const,
                      crossvul_path,
                      base_model_path,
                      rate=0.15,
                      SARD_data_path = '',
                      synthesis_data_path='',
                      set_eos=True):

    crossvul_data = read_json(crossvul_path)


    if synthesis_data_path != '':
        new_crossvul_data = []
        for d in crossvul_data:
            if len(d['renamed_slice'] ) > SYNTHESIS_LEN or d['CVE_database_id']>4500:
                new_crossvul_data.append(d)

        synthesis_data = read_json(synthesis_data_path)
        synthesis_train_data, synthesis_test_data = trans_crossvul_label(synthesis_data, rate, issynthesis=True)
        train_data, test_data = synthesis_train_data, new_crossvul_data
    else:
        crossvul_train_data, crossvul_test_data = trans_crossvul_label(crossvul_data, rate, issynthesis=False)
        train_data, test_data = crossvul_train_data, crossvul_test_data

    if SARD_data_path != '':
        data = read_json(SARD_data_path)
        train_data, test_data = data + train_data, test_data

    shuffle(train_data)
    shuffle(test_data)

    # test_data = test_data[:500]
    # Load LLaMA tokenizer
    tokenizer = AutoTokenizer.from_pretrained(
        base_model_path,
        trust_remote_code=True,
    )

    if train_const.set_eos:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    logger.info("[LLM] tokenizer initialized ...")
    train_dataset = get_tokenized_dataset(train_data, tokenizer, train_const)
    test_dataset = get_tokenized_dataset(test_data, tokenizer, train_const)

    # train_t = train_dataset.input_ids.tolist()
    # test_t = test_dataset.input_ids.tolist()
    return train_dataset, test_dataset, tokenizer
