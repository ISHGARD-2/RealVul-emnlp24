import sys

import logging
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import (
    TrainingArguments,
    DataCollatorWithPadding, T5ForSequenceClassification
)
from configs.train_const import Codet5p_770m_TrainConst as train_const
from peft import LoraConfig, TaskType, PeftModel

from configs.settings import LLM_ENV_PATH, DATA_PATH, MODEL_PATH
from core.LLM.codellama_train import MyTrainer
from core.LLM.dataset import get_crossvul_data
import torch

from utils.log import logger, log


# metric = evaluate.load('accuracy')


# def compute_metrics(eval_pred):
#     predictions, labels = eval_pred
#     predictions = np.argmax(predictions, axis=1)
#     return metric.compute(predictions=predictions, references=labels)

def train_model(train_dataset, eval_dataset, tokenizer, base_model_path, output_model_path,new_model,
                check_point_path=''):
    """

    """

    # model_config = T5Config.from_pretrained(base_model_path)
    model = T5ForSequenceClassification.from_pretrained(
        base_model_path,
        num_labels=2,
        device_map=train_const.device_map,
        output_scores=True
    )
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)
    # training_loader = DataLoader(train_dataset, batch_size=train_const.batch_size, shuffle=True)
    # testing_loader = DataLoader(eval_dataset, batch_size=1, shuffle=True)

    # Load LoRA configuration
    # Load LoRA configuration
    peft_config = LoraConfig(
        lora_alpha=train_const.lora_alpha,
        lora_dropout=train_const.lora_dropout,
        r=train_const.lora_r,
        bias="none",
        task_type=TaskType.SEQ_CLS,
    )

    # Set training parameters
    training_arguments = TrainingArguments(
        output_dir=output_model_path,
        per_device_train_batch_size=train_const.per_device_train_batch_size*2,
        gradient_accumulation_steps=train_const.gradient_accumulation_steps,
        optim=train_const.optim,
        save_steps=train_const.save_steps,
        logging_steps=train_const.logging_steps,
        learning_rate=train_const.learning_rate*5,
        weight_decay=train_const.weight_decay,
        fp16=train_const.fp16,
        # bf16=train_const.bf16,
        max_grad_norm=train_const.max_grad_norm,
        num_train_epochs=train_const.num_train_epochs,
        # max_steps=train_const.max_steps,
        warmup_steps=train_const.warmup_steps,
        group_by_length=train_const.group_by_length,
        # lr_scheduler_type=train_const.lr_scheduler_type,
        report_to="none"
    )
    logger.info("\n[LLM] Tarining ...")
    print(new_model)

    model.config.pad_token_id = model.config.eos_token_id
    model.config.use_cache = False
    trainer = MyTrainer(
        model=model,
        args=training_arguments,
        max_seq_length=train_const.max_seq_length,
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


    # model = CodeT5PClassifier(input_size=1024, hidden_size=1024, output_size=1, model=model.encoder)
    #model = torch.nn.DataParallel(model.cuda(), device_ids=[1, 2])
    # device = torch.device(train_const.device)
    # model.to(device)
    # # device = torch.device(train_const.device)
    #
    #
    # model.zero_grad()
    # loss_fn = torch.nn.CrossEntropyLoss()
    # optimizer = optim.Adam(filter(lambda p: p.requires_grad, model.parameters()), lr=train_const.learning_rate)
    #
    # max_step = math.ceil(train_const.num_epochs * len(training_loader) / train_const.gradient_accumulation_steps)
    # scheduler = get_linear_schedule_with_warmup(optimizer,
    #                                             num_warmup_steps=train_const.warmup_steps,
    #                                             num_training_steps=max_step)
    #
    # model.train()
    # for epoch in range(train_const.num_epochs):
    #     logger.info('[CodeT5P] training epoch {}'.format(epoch))
    #     correct = 0
    #     total = 0
    #     #optimizer.zero_grad()
    #     for step, data in enumerate(tqdm(training_loader)):
    #         inputs, labels = data['input_ids'].to(train_const.device), data['labels'].to(train_const.device)
    #         optimizer.zero_grad()
    #
    #         outputs = model(input_ids=inputs, labels=labels)
    #         loss = outputs.loss
    #         loss.backward()
    #         torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
    #
    #         optimizer.step()
    #         scheduler.step()
    #
    #         # if (step + 1) % int(train_const.gradient_accumulation_steps * 10) == 0:
    #         if (step + 1) % int(20) == 0:
    #             logger.debug('\nloss: {v1}\tstep: {v2}\tlearning_rate: {v3}'.format(
    #                 v1=str(loss.item()),
    #                 v2=str(int((step+1) / train_const.gradient_accumulation_steps)),
    #                 v3=optimizer.state_dict()['param_groups'][0]['lr']))


        #     optimizer.zero_grad()
        #     outputs = model(inputs)
        #     logits = outputs.logits
        #     loss = loss_fn(logits, labels)
        #
        #
        #
        #     loss.backward()
        #     optimizer.step()
        #
        #     pred = logits[0]
        #     predicted = torch.argmax(pred)
        #     total += labels.size(0)
        #     correct += (predicted == labels).sum().item()
        # accuracy = correct / total
        # logger.info(f"Accuracy: {accuracy:.2f}")
        #
        # torch.save(model.state_dict(), new_model+'epoch-'+str(epoch))

        # with torch.no_grad():
        #     correct = 0
        #     total = 0
        #     for i, data in enumerate(testing_loader):
        #         inputs, labels = data['input_ids'].to(train_const.device), data['labels'].to(train_const.device)
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
    # torch.save(model.state_dict(), new_model)
    logger.info("[LLM] Training is over")

    return new_model


def eval_model(eval_dataset, tokenizer, new_model_path, base_model_path):
    logger.info("Start eval")
    logger.info("checkpoint path: {}".format(new_model_path))
    logger.info("Load model")

    raw_data = eval_dataset.raw_data
    model = T5ForSequenceClassification.from_pretrained(
        base_model_path,
        num_labels=2,
        device_map=train_const.device_map,
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
    count = 0
    sum = len(eval_dataset.labels.tolist())
    with torch.no_grad():
        tr_data = DataLoader(eval_dataset, batch_size=16, shuffle=False)
        device = torch.device('cuda')
        for step, batch in enumerate(tqdm(tr_data)):
            # text = raw_data['text'][step]

            batch = tuple(batch[t].to(device) for t in batch)
            b_input_ids, b_input_mask, b_labels = batch

            test_output = lora_model(input_ids=b_input_ids, attention_mask=b_input_mask, labels=b_labels)

            eval_predictions = torch.argmax(test_output.logits, dim=1).tolist()

            label = b_labels.tolist()

            for label, pred in zip(label, eval_predictions):
                result = {'file_name': raw_data['file_name'][count], 'label': label, 'pred': pred}
                text = raw_data['text'][count]
                count += 1
                result_list.append(result)

                if label == 0 and pred == 0:
                    evalmatrix[0] += 1
                elif label == 0 and pred == 1:
                    evalmatrix[1] += 1
                    # logger.debug("\nSafe sample : \tpred error: 1\n{}".format(text))
                elif label == 1 and pred == 0:
                    evalmatrix[2] += 1
                    #logger.debug("\nVulnerable sample : \tpred error: 0\n{}".format(text))
                elif label == 1 and pred == 1:
                    evalmatrix[3] += 1
                    # logger.debug("\nVulnerable sample : \tpred correct: 1\n{}".format(text))
                else:
                    evalmatrix[4] += 1
    logger.info('\nevalmatrix: {matrix}\n\tTP: {tp}\tFN: {fn}\n\tFP: {fp}\tTN: {tn}\n\t:'.format(
        matrix=str(evalmatrix),
        tn=str(evalmatrix[0] / sum), fp=str(evalmatrix[1] / sum),
        fn=str(evalmatrix[2] / sum), tp=str(evalmatrix[3] / sum)))

    accuracy_score = (evalmatrix[0]+evalmatrix[3])/(evalmatrix[0]+evalmatrix[1]+evalmatrix[2]+evalmatrix[3])
    precision_score = (evalmatrix[3])/ (evalmatrix[3]+evalmatrix[1])
    recall_score = (evalmatrix[3])/ (evalmatrix[3]+evalmatrix[2])
    F1_score = (2*precision_score*recall_score)/(precision_score+recall_score)

    logger.info('\nAccuracy: {Accuracy}\n\tRecall: {Recall}\tPrecision: {Precision}\n\tF1: {F1}\n\t:'.format(
        Accuracy=str(accuracy_score),
        Recall=str(recall_score),
        Precision=str(precision_score),
        F1=str(F1_score)))
    logger.info("over")


def main():
    log(logging.DEBUG)

    SARD_data_path = DATA_PATH + '/SARD/SARD_php_vulnerability_79.json'
    crossvul_data_path = DATA_PATH + '/CVI_10001/dataset_out_all_unique.json'
    synthesis_data_path = DATA_PATH + '/CVI_10001/dataset_synthesis_79.json'

    # codeT5+
    base_model_path = LLM_ENV_PATH + 'codeT5/codet5p-770m/'

    test_id = 1
    basemodel = 'codet5p'
    output_model_path = MODEL_PATH + '/output/' + basemodel + '-770m/test' + str(test_id) + '/'
    new_model_path = output_model_path + "tuned_model_epoch2"

    # data
    train_dataset, test_dataset, tokenizer = get_crossvul_data(
        crossvul_data_path,
        base_model_path,
        SARD_data_path='',
        synthesis_data_path=synthesis_data_path,
        set_eos=False)

    # train
    check_point_path = output_model_path + "checkpoint-100"
    train_model(train_dataset, test_dataset, tokenizer,
                base_model_path,
                output_model_path,
                new_model_path,
                check_point_path='')

    # test
    # eval_start = 50
    # eval_end = 250
    # for step in range(eval_start, eval_end+1, train_const.save_steps):
    #     check_point_path = output_model_path + "checkpoint-"+str(step)
    #
    #     eval_model(test_dataset, tokenizer, check_point_path, base_model_path)
    eval_model(test_dataset, tokenizer, new_model_path, base_model_path)


if __name__ == '__main__':
    main()
