import sys

import logging
from scipy.special import softmax
from sklearn.metrics import accuracy_score
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import (
    AutoModelForSequenceClassification,
    TrainingArguments,
    DataCollatorWithPadding, BatchEncoding, LlamaForSequenceClassification
)
import train_const as my_c
from peft import LoraConfig, TaskType, PeftModel
from trl import SFTTrainer

from configs.settings import LLM_ENV_PATH, DATA_PATH, MODEL_PATH
from core.LLM.dataset import  get_crossvul_data
import torch
from utils.log import logger, log
from sklearn import metrics

# metric = evaluate.load('accuracy')


# def compute_metrics(eval_pred):
#     predictions, labels = eval_pred
#     predictions = np.argmax(predictions, axis=1)
#     return metric.compute(predictions=predictions, references=labels)


class MyTrainer(SFTTrainer):

    def compute_loss(self, model, inputs, return_outputs=False):
        """
        How the loss is computed by Trainer. By default, all models return the loss in the first element.
        Subclass and override for custom behavior.
        """

        # data_path = DATA_PATH + '/SARD/SARD_php_vulnerability.json'
        # base_model_path = LLM_ENV_PATH + 'models/7b/'
        # output_model_path = MODEL_PATH + '/output/codellama/test1/'
        # check_point_path = output_model_path + "checkpoint-400"
        # new_model_path = output_model_path + "tuned_model"
        #
        # # data
        # train_dataset, test_dataset, tokenizer = get_data(data_path, base_model_path)
        #
        # result_list = []
        # # TN FP FN TP
        # evalmatrix = [0, 0, 0, 0, 0]
        # sum = len(test_dataset.labels.tolist())
        # tr_data = DataLoader(train_dataset, batch_size=1, shuffle=False)
        # device = torch.device('cuda')
        # for step, batch in enumerate(tr_data):
        #     if step >= 100:
        #         break
        #     batch = tuple(batch[t].to(device) for t in batch)
        #     b_input_ids, b_input_mask, b_labels = batch
        #
        #     test_output = model(b_input_ids,
        #                              attention_mask=b_input_mask)
        #
        #     eval_predictions = torch.argmax(test_output.logits, dim=1).tolist()[0]
        #
        #     label = b_labels.tolist()[0]
        #     print(eval_predictions,' ： ', label)

        outputs = model(**inputs)
        labels = inputs['labels']

        # code for calculating accuracy
        # preds = outputs.logits.detach().argmax(axis=1).tolist()
        # acc1 = accuracy_score(labels.tolist(), preds)
        # self.log({'accuracy_score': acc1})
        # end code for calculating accuracy

        logits = outputs.logits
        loss_fn = torch.nn.CrossEntropyLoss()
        loss = loss_fn(logits, labels)
        return (loss, outputs) if return_outputs else loss


def train_codellama_model(train_dataset, eval_dataset, tokenizer, base_model_path, output_model_path,
                          check_point_path=''):
    """

    """
    new_model = output_model_path + "tuned_model"
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    # bnb_config = get_bnb_config()
    model = LlamaForSequenceClassification.from_pretrained(
        base_model_path,
        num_labels=2,
        device_map=my_c.device_map,
        output_scores=True
    )

    # Load LoRA configuration
    peft_config = LoraConfig(
        lora_alpha=my_c.lora_alpha,
        lora_dropout=my_c.lora_dropout,
        r=my_c.lora_r,
        bias="none",
        task_type=TaskType.SEQ_CLS,
    )

    # Set training parameters
    training_arguments = TrainingArguments(
        output_dir=output_model_path,
        num_train_epochs=my_c.num_train_epochs,
        per_device_train_batch_size=my_c.per_device_train_batch_size,
        gradient_accumulation_steps=my_c.gradient_accumulation_steps,
        optim=my_c.optim,
        save_steps=my_c.save_steps,
        logging_steps=my_c.logging_steps,
        learning_rate=my_c.learning_rate,
        weight_decay=my_c.weight_decay,
        fp16=my_c.fp16,
        # bf16=my_c.bf16,
        max_grad_norm=my_c.max_grad_norm,
        max_steps=my_c.max_steps,
        warmup_steps=my_c.warmup_steps,
        group_by_length=my_c.group_by_length,
        # lr_scheduler_type=my_c.lr_scheduler_type,
        report_to="none"
    )
    logger.info("\n[LLM] Tarining CodeLlama...")
    print(new_model)

    model.config.pad_token_id = model.config.eos_token_id
    model.config.use_cache = False
    trainer = MyTrainer(
        model=model,
        args=training_arguments,
        max_seq_length=my_c.max_seq_length,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        dataset_text_field="text",
        peft_config=peft_config,
        data_collator=data_collator,
        # compute_metrics=compute_metrics
    )

    if torch.__version__ >= "2" and sys.platform != "win32":
        logger.info("compiling the model")
        model = torch.compile(model)

    # Train model
    logger.info("[LLM] Go training")

    if check_point_path != '':
        trainer.train(resume_from_checkpoint=True)
    else:
        trainer.train()

    trainer.save_model(new_model)
    logger.info("[LLM] Training is over")

    return new_model


def eval_codellama_model(eval_dataset, tokenizer, new_model_path, base_model_path):
    logger.info("Start eval")
    logger.info("Load model")

    raw_data = eval_dataset.raw_data
    model = AutoModelForSequenceClassification.from_pretrained(
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
    evalmatrix = [0, 0, 0, 0]
    sum = len(eval_dataset.labels.tolist())
    with torch.no_grad():
        tr_data = DataLoader(eval_dataset, batch_size=16, shuffle=False)
        device = torch.device('cuda')
        for step, batch in enumerate(tqdm(tr_data)):
            text = raw_data['text'][step]

            batch = tuple(batch[t].to(device) for t in batch)
            b_input_ids, b_input_mask, b_labels = batch

            test_output = lora_model(input_ids=b_input_ids, attention_mask=b_input_mask, labels=b_labels)


            eval_predictions = torch.argmax(test_output.logits, dim=1).tolist()

            label = b_labels.tolist()

            for label, pred in zip(label, eval_predictions):
                if label == 0 and pred == 0:
                    evalmatrix[0] += 1
                elif label == 0 and pred == 1:
                    evalmatrix[1] += 1
                    #logger.debug("\nSafe sample : \tpred error: 1\n{}".format(text))
                elif label == 1 and pred == 0:
                    evalmatrix[2] += 1
                    #logger.debug("\nVulnerable sample : \tpred error: 0\n{}".format(text))
                elif label == 1 and pred == 1:
                    evalmatrix[3] += 1
                    #logger.debug("\nVulnerable sample : \tpred correct: 1\n{}".format(text))
                else:
                    evalmatrix[4] += 1
    logger.info('\nevalmatrix: {matrix}\n\tTP: {tp}\tFN: {fn}\n\tFP: {fp}\tTN: {tn}\n\t:'.format(
        matrix=str(evalmatrix),
        tn=str(evalmatrix[0] / sum), fp=str(evalmatrix[1] / sum),
        fn=str(evalmatrix[2] / sum), tp=str(evalmatrix[3] / sum)))

    logger.info("over")


def main():
    log(logging.DEBUG)

    SARD_data_path = DATA_PATH + '/SARD/SARD_php_vulnerability.json'
    crossvul_data_path = DATA_PATH + '/CVI_10001/dataset_out_all_unique.json'
    synthesis_data_path =  DATA_PATH + '/CVI_10001/dataset_synthesis.json'
    # crossvul_path2 = DATA_PATH + '/CVI_10001/dataset_out4.json'


    # code llama
    base_model_path = LLM_ENV_PATH + 'codellama-instruct-13b/models/7b/'

    test_id = 8
    basemodel = 'codellama'
    output_model_path = MODEL_PATH + '/output/'+basemodel+'/test'+str(test_id)+'/'
    new_model_path = output_model_path + "tuned_model"


    # data
    #train_dataset, test_dataset, tokenizer = get_data(data_path, base_model_path)
    train_dataset, test_dataset, tokenizer = get_crossvul_data(crossvul_data_path, base_model_path, SARD_data_path=SARD_data_path, synthesis_data_path=synthesis_data_path)


    #train
    check_point_path = output_model_path + "checkpoint-200"
    # train_codellama_model(train_dataset, test_dataset, tokenizer,
    #                       base_model_path, output_model_path,
    #                       check_point_path='')


    # test
    eval_start = 50
    eval_end = 300
    for step in range(eval_start, eval_end+1, my_c.save_steps):
        check_point_path = output_model_path + "checkpoint-"+str(step)
        logger.info("checkpoint path: {}".format(check_point_path))

        eval_codellama_model(test_dataset, tokenizer, check_point_path, base_model_path)


if __name__ == '__main__':
    main()
