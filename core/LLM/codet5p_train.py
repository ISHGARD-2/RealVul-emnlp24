import sys

import logging
from scipy.special import softmax
from sklearn.metrics import accuracy_score
from torch import nn, optim
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import (
    AutoModelForSequenceClassification,
    TrainingArguments,
    DataCollatorWithPadding, BatchEncoding, T5ForSequenceClassification, AutoTokenizer, AutoModel,
    T5ForConditionalGeneration, T5EncoderModel, T5Model, T5Config
)
import train_const as my_c
from peft import LoraConfig, TaskType, PeftModel
from trl import SFTTrainer

from configs.settings import LLM_ENV_PATH, DATA_PATH, MODEL_PATH
from core.LLM.dataset import get_data, get_crossvul_data
import torch

from core.LLM.model import CodeT5PClassifier
from utils.log import logger, log


# metric = evaluate.load('accuracy')


# def compute_metrics(eval_pred):
#     predictions, labels = eval_pred
#     predictions = np.argmax(predictions, axis=1)
#     return metric.compute(predictions=predictions, references=labels)

def train_model(train_dataset, eval_dataset, tokenizer, base_model_path, output_model_path,
                          check_point_path=''):
    """

    """
    new_model = output_model_path + "tuned_model"

    #model_config = T5Config.from_pretrained(base_model_path)
    model = T5ForSequenceClassification.from_pretrained(base_model_path)

    training_loader = DataLoader(train_dataset, batch_size=my_c.batch_size, shuffle=True)
    testing_loader = DataLoader(eval_dataset, batch_size=1, shuffle=True)

    # Load LoRA configuration
    # model = CodeT5PClassifier(input_size=1024, hidden_size=1024, output_size=1, model=model.encoder)
    # model = torch.nn.DataParallel(model, device_ids=[1, 2]).cuda()
    # device = torch.device(my_c.device)
    model.to(my_c.device)


    loss_fn = torch.nn.CrossEntropyLoss()
    optimizer = optim.Adam(filter(lambda p: p.requires_grad, model.parameters()), lr=0.001)
    num_epochs = 5

    model.train()
    for epoch in range(num_epochs):
        logger.debug('[CodeT5P] training epoch {}'.format(epoch))
        correct = 0
        total = 0
        for i, data in enumerate(tqdm(training_loader)):
            inputs, labels = data['input_ids'].to(my_c.device), data['labels'].to(my_c.device)
            optimizer.zero_grad()
            outputs = model(inputs)
            logits = outputs.logits
            loss = loss_fn(logits, labels)
            loss.backward()
            optimizer.step()

            pred = logits[0]
            predicted = torch.argmax(pred)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
        accuracy = correct / total
        print(f"Accuracy: {accuracy:.2f}")
        #
        # torch.save(model.state_dict(), new_model+'epoch-'+str(epoch))

        # with torch.no_grad():
        #     correct = 0
        #     total = 0
        #     for i, data in enumerate(testing_loader):
        #         inputs, labels = data['input_ids'].to(my_c.device), data['labels'].to(my_c.device)
        #         outputs = model(inputs)
        #
        #         pred = outputs.logits[0]
        #
        #         predicted = torch.argmax(pred)
        #
        #         total += labels.size(0)
        #         correct += (predicted == labels).sum().item()
        #     accuracy = correct / total
        #     print(f"Accuracy: {accuracy:.2f}")
    torch.save(model.state_dict(), new_model )
    logger.info("[LLM] Training is over")

    return new_model


def eval_model(eval_dataset, tokenizer, new_model_path, base_model_path):
    logger.info("Start eval")
    logger.info("Load model")

    raw_data = eval_dataset.raw_data
    model = T5ForSequenceClassification.from_pretrained(
        base_model_path,
        num_labels=2,
        device_map=my_c.device_map,
        output_scores=True)
    lora_model = PeftModel.from_pretrained(model, new_model_path)
    lora_model = lora_model.merge_and_unload()

    lora_model.eval()
    # lora_model.half()

    model.config.pad_token_id = model.config.eos_token_id
    # if torch.__version__ >= "2" and sys.platform != "win32":
    #     logger.info("compiling the model")
    #     lora_model = torch.compile(lora_model)

    result_list = []
    # TN FP FN TP
    evalmatrix = [0, 0, 0, 0, 0]
    sum = len(eval_dataset.labels.tolist())
    with torch.no_grad():
        tr_data = DataLoader(eval_dataset, batch_size=1, shuffle=False)
        device = torch.device('cuda')
        for step, batch in enumerate(tqdm(tr_data)):
            text = raw_data['text'][step]

            batch = tuple(batch[t].to(device) for t in batch)
            b_input_ids, b_input_mask, b_labels = batch

            test_output = lora_model(input_ids=b_input_ids, attention_mask=b_input_mask, labels=b_labels)


            t = test_output.logits[0].cpu().numpy()
            eval_predictions = torch.argmax(test_output.logits, dim=1).tolist()[0]
            preds = softmax(t)

            pred = preds.tolist()

            label = b_labels.tolist()[0]

            result = {}
            result['label'] = label

            pred = pred.index(max(pred))
            result['pred'] = pred
            result_list.append(result)

            if label == 0 and pred == 0:
                evalmatrix[0] += 1
            elif label == 0 and pred == 1:
                evalmatrix[1] += 1
            elif label == 1 and pred == 0:
                evalmatrix[2] += 1
            elif label == 1 and pred == 1:
                evalmatrix[3] += 1
            else:
                evalmatrix[4] += 1
    logger.info('\nevalmatrix: {matrix}\n\tTP: {tp}\tFN: {fn}\n\tFP: {fp}\tTN: {tn}\n\tothers: {others}:'.format(
        matrix=str(evalmatrix),
        tn=str(evalmatrix[0] / sum), fp=str(evalmatrix[1] / sum),
        fn=str(evalmatrix[2] / sum), tp=str(evalmatrix[3] / sum),
        others=str(evalmatrix[4] / sum)))

    logger.info("over")


def main():
    log(logging.DEBUG)

    SARD_data_path = DATA_PATH + '/SARD/SARD_php_vulnerability.json'
    crossvul_data_path = DATA_PATH + '/CVI_10001/dataset_out_all_unique.json'

    # codeT5+
    base_model_path = LLM_ENV_PATH + 'codeT5/codet5p-770m/'

    test_id = 1
    basemodel = 'codet5p'
    output_model_path = MODEL_PATH + '/output/'+basemodel+'/test'+str(test_id)+'/'
    new_model_path = output_model_path + "tuned_model"


    # data
    train_dataset, test_dataset, tokenizer = get_crossvul_data(crossvul_data_path, base_model_path, SARD_data_path=SARD_data_path)



    #train
    train_model(train_dataset, test_dataset, tokenizer,
                          base_model_path, output_model_path,
                          check_point_path='')


    # test
    # for step in range(25, 201, 25):
    #     check_point_path = output_model_path + "checkpoint-"+str(step)
    #     logger.info("checkpoint path: {}".format(check_point_path))
    #
    #     eval_model(test_dataset, tokenizer, check_point_path, base_model_path)


if __name__ == '__main__':
    main()
