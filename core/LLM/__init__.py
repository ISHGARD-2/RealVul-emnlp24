import logging
import os
import sys

from transformers import T5ForSequenceClassification, LlamaForSequenceClassification, Starcoder2ForSequenceClassification

from configs.settings import DATA_PATH, LLM_ENV_PATH, MODEL_PATH
from configs.train_const import Codellama_7b_TrainConst, Starcoder2_7b_TrainConst, Codet5p_770m_TrainConst, \
    Starcoder2_3b_TrainConst, Codet5p_2b_TrainConst
from core.LLM.dataset import get_crossvul_data
from core.LLM.eval import eval_model
from core.LLM.train import train_model
from utils.log import log



LOAD_CLASS = {
    'codellama-7b':[LlamaForSequenceClassification, Codellama_7b_TrainConst],
    'codet5p-770m':[T5ForSequenceClassification, Codet5p_770m_TrainConst],
    'codet5p-2b':[T5ForSequenceClassification, Codet5p_2b_TrainConst],
    'starcoder2-3b':[Starcoder2ForSequenceClassification, Starcoder2_3b_TrainConst],
    'starcoder2-7b':[Starcoder2ForSequenceClassification, Starcoder2_7b_TrainConst]
}

def main(model_name, base_model_path, output_model_path, crossvul_data_path, synthesis_data_path, checkpoint='', eval_dataset='raw'):
    if not os.path.exists(output_model_path):
        os.makedirs(output_model_path)

    if checkpoint != '':
        check_point_path = os.path.join(output_model_path + checkpoint)
    else:
        check_point_path = ''

    new_model_path = os.path.join(output_model_path, "tuned_model")
    load_class, train_const = LOAD_CLASS[model_name]
    train_const = train_const()

    # output redirection
    # original_stdout = sys.stdout
    # fout = open(output_model_path + "log.txt", 'a+')
    # sys.stdout = fout

    # data
    # train_dataset, test_dataset, tokenizer = get_data(data_path, base_model_path)
    train_dataset, test_dataset, tokenizer = get_crossvul_data(
        train_const,
        crossvul_data_path,
        base_model_path,
        SARD_data_path='',
        synthesis_data_path=synthesis_data_path)



    # train
    # train_model(base_model_path, load_class, train_const,
    #             train_dataset, test_dataset,
    #             tokenizer, output_model_path, new_model_path,
    #                       check_point_path=check_point_path)

    # test
    eval_start = 50
    eval_end = 250
    for step in range(eval_start, eval_end+1, train_const.save_steps):
        check_point_path = os.path.join(output_model_path, "checkpoint-" + str(step))
        eval_model(base_model_path, load_class, train_const, test_dataset, tokenizer, check_point_path)


    eval_model(base_model_path, load_class, train_const, test_dataset, tokenizer, new_model_path)

    # Restore output redirection
    #sys.stdout = original_stdout


if __name__ == '__main__':
    log_path = os.path.join(MODEL_PATH, 'log.txt')
    log(logging.DEBUG, log_path)

    # define
    #model_name = 'codellama-7b'
    #model_name = 'starcoder2-7b'
    #model_name = 'starcoder2-3b'
    model_name = 'codet5p-770m'
    #model_name = 'codet5p-2b'

    eval_dataset = 'raw' #'synthesis'
    CWE = '79'

    # checkpoint = "checkpoint-300"
    checkpoint = ""

    # params process
    SARD_data_path = DATA_PATH + '/SARD/SARD_php_vulnerability_79.json'
    crossvul_data_path = DATA_PATH + '/CVI_10001/dataset_out_all_unique.json'
    synthesis_data_path = DATA_PATH + '/CVI_10001/dataset_synthesis_79.json'

    if model_name == 'codellama-7b':
        test_id = 9
        base_model_path = LLM_ENV_PATH + 'codellama-instruct-13b/models/7b/'
        output_model_path = MODEL_PATH + '/output/codellama-7b/test' + str(test_id) + '/'

    elif model_name == 'codet5p-770m':
        test_id = 2
        base_model_path = LLM_ENV_PATH + 'codeT5/codet5p-770m/'
        output_model_path = MODEL_PATH + '/output/codet5p-770m/test' + str(test_id) + '/'

    elif model_name == 'codet5p-2b':
        test_id = 1
        base_model_path = LLM_ENV_PATH + 'codeT5/codet5p-2b/'
        output_model_path = MODEL_PATH + '/output/codet5p-2b/test' + str(test_id) + '/'

    elif model_name == 'starcoder2-3b':
        test_id = 1
        base_model_path = LLM_ENV_PATH + 'starcoder2/starcoder2-3b/'
        output_model_path = MODEL_PATH + '/output/starcoder2-3b/test' + str(test_id) + '/'

    elif model_name == 'starcoder2-7b':
        test_id = 1
        base_model_path = LLM_ENV_PATH + 'starcoder2/starcoder2-7b/'
        output_model_path = MODEL_PATH + '/output/starcoder2-7b/test' + str(test_id) + '/'
    else:
        exit()

    main(model_name,
         base_model_path,
         output_model_path,
         crossvul_data_path,
         synthesis_data_path,
         checkpoint='',
         eval_dataset=eval_dataset)







