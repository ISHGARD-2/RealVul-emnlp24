import logging
import os
import sys

from transformers import T5ForSequenceClassification, LlamaForSequenceClassification, \
    Starcoder2ForSequenceClassification, LlamaForCausalLM

from configs.settings import DATA_PATH, LLM_ENV_PATH, MODEL_PATH
from configs.train_const import Codellama_7b_TrainConst, Starcoder2_7b_TrainConst, Codet5p_770m_TrainConst, \
    Starcoder2_3b_TrainConst, Codet5_base_TrainConst
from core.LLM.dataset import get_crossvul_data
from core.LLM.eval import eval_model
from core.LLM.train import train_model
from utils.log import log, logger

LOAD_CLASS = {
    'codellama-7b': [LlamaForSequenceClassification, Codellama_7b_TrainConst],
    'codet5p-770m': [T5ForSequenceClassification, Codet5p_770m_TrainConst],
    'codet5-base': [T5ForSequenceClassification, Codet5_base_TrainConst],
    'starcoder2-3b': [Starcoder2ForSequenceClassification, Starcoder2_3b_TrainConst],
    'starcoder2-7b': [Starcoder2ForSequenceClassification, Starcoder2_7b_TrainConst]
}


def main(model_name, base_model_path, output_model_path, crossvul_data_path, synthesis_data_path,
         train_task, train_mode, checkpoint='', train=True):
    """
        CWE:
            79, 89
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
    os.environ['TOKENIZERS_PARALLELISM'] = 'False'

    logger.info(f"[LLM] info: \n"
                f"model_name: {model_name}\n"
                f"train_task: {train_task}\n"
                f"train_mode: {train_mode}\n"
                f"base_model_path: {base_model_path}\n"
                f"output_model_path: {output_model_path}\n")

    if not os.path.exists(output_model_path):
        os.makedirs(output_model_path)

    if checkpoint != '':
        check_point_path = os.path.join(output_model_path, checkpoint)
    else:
        check_point_path = ''

    new_model_path = os.path.join(output_model_path, "tuned_model")

    load_class, train_const = LOAD_CLASS[model_name]
    train_const = train_const()

    # output redirection
    # original_stdout = sys.stdout
    # fout = open(output_model_path + "log.txt", 'a+')
    # sys.stdout = fout

    if 'random' in train_mode:
        # reduce train steps
        train_const.num_train_epochs = 2
    elif 'unseen' in train_mode:
        train_const.num_train_epochs = 3
    if CWE == '89':
        train_const.num_train_epochs += 1
    if 'without_slice' in train_mode:
        train_const.num_train_epochs *= 2

    # data
    logger.info("[LLM] Data Processing ...")
    # train_dataset, test_dataset, tokenizer = get_data(data_path, base_model_path)
    train_dataset, eval_dataset, test_dataset, tokenizer = get_crossvul_data(
        train_const,
        crossvul_data_path,
        synthesis_data_path,
        base_model_path,
        train_mode,
        train_task,
        CWE)

    # train
    if train:
        logger.info("[LLM] Training ...")
        train_model(base_model_path, load_class, train_const, train_task,
                    train_dataset, eval_dataset, tokenizer,
                    output_model_path, new_model_path,
                    check_point_path=check_point_path)

    # test
    logger.info("[LLM] Evaling ... ")
    # eval_start = 50
    # eval_end = 250
    # for step in range(eval_start, eval_end+1, train_const.save_steps):
    #     check_point_path = os.path.join(output_model_path, "checkpoint-" + str(step))
    #     eval_model(base_model_path, load_class, train_const, test_dataset, tokenizer, check_point_path)

    eval_model(base_model_path, load_class, train_const, test_dataset, new_model_path)

    # Restore output redirection
    # sys.stdout = original_stdout


def get_pathinfo(model_name, train_mode, train_task, CWE):
    if model_name == 'codellama-7b':
        output_model_path = MODEL_PATH + '/codellama-7b/' + train_mode + '_' + train_task + '_' + CWE + '/'

    elif model_name == 'codet5p-770m':
        output_model_path = MODEL_PATH + '/codet5p-770m/' + train_mode + '_' + train_task + '_' + CWE + '/'

    elif model_name == 'codet5-base':
        output_model_path = MODEL_PATH + '/codet5-base/' + train_mode + '_' + train_task + '_' + CWE + '/'

    elif model_name == 'starcoder2-3b':
        output_model_path = MODEL_PATH + '/starcoder2-3b/' + train_mode + '_' + train_task + '_' + CWE + '/'

    elif model_name == 'starcoder2-7b':
        output_model_path = MODEL_PATH + '/starcoder2-7b/' + train_mode + '_' + train_task + '_' + CWE + '/'
    else:
        exit()


    return output_model_path



if __name__ == '__main__':
    log_path = os.path.join(MODEL_PATH, 'log.txt')
    log(logging.DEBUG, log_path)

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

    # train_mode = 'unseen'
    # train_task = 'seq_cls'
    # CWE = '89'
    # # checkpoint = ""
    #
    # # define
    # # model_name = 'codellama-7b'
    # # model_name = 'starcoder2-7b'
    # # model_name = 'starcoder2-3b'
    # model_name = 'codet5p-770m'
    #
    # # params process
    # crossvul_data_path = DATA_PATH + '/dataset_unique_'+CWE+'.json'
    # synthesis_data_path = DATA_PATH + '/dataset_synthesis_'+CWE+'.json'
    #
    # base_model_path, output_model_path = get_pathinfo(model_name, train_mode, train_task, CWE)
    #
    # main(model_name,
    #      base_model_path,
    #      output_model_path,
    #      crossvul_data_path,
    #      synthesis_data_path,
    #      train_task,
    #      train_mode,
    #      checkpoint=''
    #      )









    CWE = '89'
    train_task = 'seq_cls'

    # params process
    crossvul_data_path = DATA_PATH + '/dataset_unique_' + CWE + '.json'
    synthesis_data_path = DATA_PATH + '/dataset_synthesis_' + CWE + '.json'

    # crossvul_data_path = DATA_PATH + '/samples_by_fix_' + CWE + '.json'


    train_mode = 'unseen'

    # define
    model_name = 'codellama-7b'
    # model_name = 'starcoder2-7b'
    # model_name = 'starcoder2-3b'
    # model_name = 'codet5p-770m'
    # model_name = 'codet5-base'

    base_model_path = LLM_ENV_PATH + 'codellama-instruct-13b/models/7b/'
    # base_model_path = LLM_ENV_PATH + 'codeT5/codet5p-770m/'
    # base_model_path = LLM_ENV_PATH + 'codeT5/codet5-base/'
    # base_model_path = LLM_ENV_PATH + 'starcoder2/starcoder2-3b/'
    # base_model_path = LLM_ENV_PATH + 'starcoder2/starcoder2-7b/'

    output_model_path = get_pathinfo(model_name, train_mode, train_task, CWE)

    main(model_name,
         base_model_path,
         output_model_path,
         crossvul_data_path,
         synthesis_data_path,
         train_task,
         train_mode,
         checkpoint='',
         train=False
         )

    train_mode = 'unseen'

    # define
    # model_name = 'codellama-7b'
    model_name = 'starcoder2-7b'
    # model_name = 'starcoder2-3b'
    # model_name = 'codet5p-770m'
    # model_name = 'codet5-base'

    base_model_path, output_model_path = get_pathinfo(model_name, train_mode, train_task, CWE)

    main(model_name,
         base_model_path,
         output_model_path,
         crossvul_data_path,
         synthesis_data_path,
         train_task,
         train_mode,
         checkpoint='',
         train=False
         )

    train_mode = 'unseen'

    # define
    # model_name = 'codellama-7b'
    # model_name = 'starcoder2-7b'
    model_name = 'starcoder2-3b'
    # model_name = 'codet5p-770m'
    # model_name = 'codet5-base'

    base_model_path, output_model_path = get_pathinfo(model_name, train_mode, train_task, CWE)

    main(model_name,
         base_model_path,
         output_model_path,
         crossvul_data_path,
         synthesis_data_path,
         train_task,
         train_mode,
         checkpoint='',
         train=False
         )

    train_mode = 'unseen'

    # define
    # model_name = 'codellama-7b'
    #model_name = 'starcoder2-7b'
    # model_name = 'starcoder2-3b'
    model_name = 'codet5p-770m'
    # model_name = 'codet5-base'

    base_model_path, output_model_path = get_pathinfo(model_name, train_mode, train_task, CWE)

    main(model_name,
         base_model_path,
         output_model_path,
         crossvul_data_path,
         synthesis_data_path,
         train_task,
         train_mode,
         checkpoint='',
         train=False
         )

    train_mode = 'unseen'

    # define
    # model_name = 'codellama-7b'
    # model_name = 'starcoder2-7b'
    # model_name = 'starcoder2-3b'
    # model_name = 'codet5p-770m'
    model_name = 'codet5-base'

    base_model_path, output_model_path = get_pathinfo(model_name, train_mode, train_task, CWE)

    main(model_name,
         base_model_path,
         output_model_path,
         crossvul_data_path,
         synthesis_data_path,
         train_task,
         train_mode,
         checkpoint='',
         train=False
         )





