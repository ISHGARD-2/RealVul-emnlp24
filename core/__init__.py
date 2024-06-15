import os.path
import sys
import time
import logging
import traceback

import argparse

from configs.settings import RESULT_PATH, PROJECT_DIRECTORY
from core.LLM import get_pathinfo
from core.processing import sample_preprocess, synthesis
from utils.file import Directory
from utils.log import log, logger
from utils.my_utils import ParseArgs

from core.sampling.func_call import FuncCall
from core.sampling.engine import scan


def parser_format():

    parser = argparse.ArgumentParser()
    ## parameters
    parser.add_argument("--task", default='Evaluation', type=str, required=True,
                        help="Task to do(Sampling, Preprocessing, Training, Evaluation or Synthesis).")
    parser.add_argument("--cwe", default='79', type=str, required=False,
                        help="Type of CWE (79 or 89).")

    # Sampling
    parser.add_argument("--sampling_target_dir", default='', type=str, required=False,
                        help="Target directory for Sampling.")
    parser.add_argument("--sampling_mode", default='test', type=str, required=False,
                        help="mode of Sampling.")
    parser.add_argument("--sampling_output_dir", default='./result/snippet/', type=str, required=False,
                        help="Output directory of Sampling.")

    # Preprocessing
    parser.add_argument("--prep_target_file", default='', type=str, required=False,
                        help="Target json file for Preprocessing.")
    parser.add_argument("--prep_output_file", default='', type=str, required=False,
                        help="Output json file.")

    # Training and Evaluation
    parser.add_argument("--crossvul_dataset", default='', type=str, required=False,
                        help="Json file from real-world CrossVul dataset for Fine-tuning.")
    parser.add_argument("--synthesis_dataset", default='', type=str, required=False,
                        help="Json file from Synthesis for Fine-tuning.")
    parser.add_argument("--train_mode", default='random', type=str, required=False,
                        help="Train mode of Fine-tuning. ")
    parser.add_argument("--base_model", default='codellama-7b', type=str, required=False,
                        help="Base model for Fine-tuning. ")
    parser.add_argument("--base_model_dir", default='', type=str, required=False,
                        help="Base model directory for Fine-tuning. ")

    # Synthesis
    parser.add_argument("--sard_samples_file", default='', type=str, required=False,
                        help="Json file of SARD samples for Synthesis.")
    parser.add_argument("--crossvul_samples_file", default='', type=str, required=False,
                        help="Json file of crossvu samples for Synthesis.")
    parser.add_argument("--synthesis_target_dir", default='', type=str, required=False,
                        help="Target directory of real-world projects for synthesis.")

    args = parser.parse_args()

    if args.cwe not in ['79', '89']:
        raise ValueError("Unknown CWE id")
    if args.task not in ['Sampling', 'Preprocessing', 'Training', 'Evaluation', 'Synthesis']:
        raise ValueError('Unknown task: {}'.format(args.task))

    return args


def sampling(args):
    # prepare args
    mode = args.sampling_mode
    target_path = str(os.path.join(PROJECT_DIRECTORY, args.sampling_target_dir))
    store_path = str(os.path.join(PROJECT_DIRECTORY, args.sampling_output_dir))

    if args.sampling_target_dir == '' or not os.path.isdir(target_path):
        raise ValueError("Unknown sampling target directory")

    CWE = args.cwe
    if CWE == '79':
        rule = '10001'
    elif CWE == '89':
        rule = '10002'
    else:
        raise ValueError("Unknown CWE id")

    # parse target mode
    pa = ParseArgs(target_path, "csv", "", rule)
    target_mode = pa.target_mode

    # target directory
    target_directory = pa.target_directory(target_mode)
    logger.info('[CLI] Target : {d}'.format(d=target_directory))

    # static analyse files info
    files, file_count, time_consume = Directory(target_directory).collect_files()
    logger.info('[CLI] [STATISTIC] Files: {fc}, Extensions:{ec}, Consume: {tc}'.format(fc=file_count, ec=len(files),
                                                                                       tc=time_consume))

    # generate function call relationship
    func_call = FuncCall(target_directory, files)
    func_call.main(mode)

    # scan
    scan(func_call, target_directory=target_directory, store_path=store_path, special_rules=pa.special_rules,
         files=func_call.files,
         mode=mode)


def preprocessing(args):
    target_file = str(os.path.join(PROJECT_DIRECTORY, args.prep_target_file))
    output_file = str(os.path.join(PROJECT_DIRECTORY, args.prep_output_file))

    if args.prep_target_file == '' or not os.path.isfile(target_file):
        raise ValueError("Unknown preprocessing target json file")

    CWE = args.cwe

    sample_preprocess.main(target_file, output_file, CWE)


def finetune(args):
    CWE = args.cwe
    train_task = 'seq_cls'
    train_mode = args.train_mode
    model_name = args.base_model
    crossvul_data_path = str(os.path.join(PROJECT_DIRECTORY, args.crossvul_dataset))
    synthesis_data_path = str(os.path.join(PROJECT_DIRECTORY, args.synthesis_dataset))
    base_model_path = str(os.path.join(PROJECT_DIRECTORY, args.base_model_dir))

    if args.crossvul_dataset == '' or not os.path.isfile(crossvul_data_path):
        raise ValueError("Unknown crossvul dataset json file for finetuning")
    if args.synthesis_dataset == '' or not os.path.isfile(synthesis_data_path):
        raise ValueError("Unknown synthesis dataset json file for finetuning")
    if args.base_model_dir == '' or not os.path.isdir(base_model_path):
        raise ValueError("Unknown synthesis dataset json file for finetuning")
    if args.base_model not in ['codellama-7b', 'starcoder2-7b', 'starcoder2-3b', 'codet5p-770m', 'codet5-base']:
        raise ValueError("Unknown base model")
    if args.train_mode not in [
        'random',
        'unseen',
        'random_without_slice',
        'unseen_without_slice',
        'random_without_preprocess',
        'unseen_without_preprocess']:
        raise ValueError("Unknown train mode")

    if args.task == 'Training':
        need_train = True
    else:
        need_train = False

    output_model_path = get_pathinfo(model_name, train_mode, train_task, CWE)

    LLM.main(model_name,
             base_model_path,
             output_model_path,
             crossvul_data_path,
             synthesis_data_path,
             train_task,
             train_mode,
             CWE,
             checkpoint='',
             train=need_train
             )


def synthes(args):
    CWE = args.cwe
    SARD_data_path = str(os.path.join(PROJECT_DIRECTORY, args.sard_samples_file))
    crossvul_data_path = str(os.path.join(PROJECT_DIRECTORY, args.crossvul_samples_file))
    clear_target_directory = str(os.path.join(PROJECT_DIRECTORY, args.synthesis_target_dir))

    if args.sard_samples_file == '' or not os.path.isfile(SARD_data_path):
        raise ValueError("Unknown SARD json file for synthesis")
    if args.crossvul_samples_file == '' or not os.path.isfile(crossvul_data_path):
        raise ValueError("Unknown synthesis dataset json file for synthesis")
    if args.synthesis_target_dir == '' or not os.path.isdir(clear_target_directory):
        raise ValueError("Unknown synthesis dataset json file for synthesis")

    # sample data
    CWE = args.cwe
    if CWE == '79':
        insert_count = 4
    elif CWE == '89':
        insert_count = 8
    else:
        raise ValueError("Unknown CWE id")

    synthesis.synthesis(SARD_data_path, crossvul_data_path, clear_target_directory, CWE=CWE, insert_count=insert_count)


def main():
    try:
        # arg parse
        # log
        log(logging.DEBUG)
        logger.debug('[INIT] set logging level: {}'.format(logging.getLogger().level))

        # args
        args = parser_format()

        # prepare args
        if args.task == 'Sampling':
            sampling(args)
        elif args.task == 'Preprocessing':
            preprocessing(args)
        elif args.task == 'Training' or args.task == 'Evaluation':
            finetune(args)
        elif args.task == 'Synthesis':
            synthes(args)

    except KeyboardInterrupt:
        logger.warning("[+++RealVul+++] Keyboard Stop.")
        sys.exit(0)

    except Exception as e:
        exc_msg = traceback.format_exc()
        logger.warning('[+++RealVul+++] Exception:' + exc_msg)


if __name__ == '__main__':
    main()
