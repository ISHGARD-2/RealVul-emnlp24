import torch
from peft import PeftModel
from torch.utils.data import DataLoader
from tqdm import tqdm

from utils.log import logger


def eval_model(base_model_path, load_class, train_const, eval_dataset, tokenizer, new_model_path):
    logger.info("Start eval")
    logger.info("checkpoint path: {}".format(new_model_path))
    logger.info("Load model")

    model = load_class.from_pretrained(
        base_model_path,
        num_labels=2,
        device_map=train_const.device_map,
        output_scores=True
    )

    raw_data = eval_dataset.raw_data

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
        tr_data = DataLoader(eval_dataset, batch_size=train_const.per_device_eval_batch_size, shuffle=False)
        device = torch.device('cuda')
        for step, batch in enumerate(tqdm(tr_data)):
            #text = raw_data['text'][step]

            batch = tuple(batch[t].to(device) for t in batch)
            b_input_ids, b_input_mask, b_labels = batch

            test_output = lora_model(input_ids=b_input_ids, attention_mask=b_input_mask, labels=b_labels)


            eval_predictions = torch.argmax(test_output.logits, dim=1).tolist()

            label = b_labels.tolist()


            for label, pred in zip(label, eval_predictions):
                result = {'file_name': raw_data['file_name'][count], 'label': label, 'pred':pred}
                text = raw_data['text'][count]
                count += 1
                result_list.append(result)

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

    accuracy_score = (evalmatrix[3] + evalmatrix[0]) / (evalmatrix[0] + evalmatrix[1] + evalmatrix[2] + evalmatrix[3])

    if evalmatrix[3] == 0:
        precision_score, recall_score, F1_score = 0, 0, 0
    else:
        precision_score = (evalmatrix[3]) / (evalmatrix[3] + evalmatrix[1])
        recall_score = (evalmatrix[3]) / (evalmatrix[3] + evalmatrix[2])
        F1_score = (2 * precision_score * recall_score) / (precision_score + recall_score)

    logger.info('\nAccuracy: {Accuracy}\nRecall: {Recall}\nPrecision: {Precision}\nF1: {F1}\n\t:'.format(
        Accuracy=str(accuracy_score),
        Recall=str(recall_score),
        Precision=str(precision_score),
        F1=str(F1_score)))
    logger.info("over")