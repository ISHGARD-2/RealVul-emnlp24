import os.path
import sys
import time
import logging
import traceback

import argparse

from configs.settings import RESULT_PATH
from utils.file import Directory
from utils.log import log, logger
from utils.my_utils import ParseArgs

from core.sampling.func_call import FuncCall
from core.sampling.engine import scan


def args_prepare(args):
    # parse target mode
    pa = ParseArgs(args.target, "csv", "", args.rule)
    target_mode = pa.target_mode

    # target directory
    logger.info('[CLI] Target Mode: {}'.format(target_mode))
    target_directory = pa.target_directory(target_mode)
    logger.info('[CLI] Target : {d}'.format(d=target_directory))

    # static analyse files info
    files, file_count, time_consume = Directory(target_directory).collect_files()
    logger.info('[CLI] [STATISTIC] Files: {fc}, Extensions:{ec}, Consume: {tc}'.format(fc=file_count, ec=len(files),
                                                                                       tc=time_consume))

    return pa, target_directory, files


def args_format():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', type=str, default='', help="target file")
    parser.add_argument('-r', '--rule', dest='rule', type=str, default=None, help="vulnerability rule")
    parser.add_argument('-m', '--mode', dest='mode', type=str, default="test", help="vulnerability rule")
    args = parser.parse_args()

    if not hasattr(args, "target") or args.target == '':
        parser.print_help()
        exit()
    logger.debug('[INIT] start Scan Task...')

    return args


def preprocess(args):
    # prepare args
    pa, target_directory, files = args_prepare(args)
    mode = args.mode

    # generate function call relationship
    func_call = FuncCall(target_directory, files)
    func_call.main(mode)

    # scan
    store_path = os.path.join(RESULT_PATH, 'snippet')
    scan(func_call, target_directory=target_directory, store_path=store_path, special_rules=pa.special_rules, files=func_call.files,
                        mode=mode)


def main():
    try:
        # arg parse
        t1 = time.time()

        # log
        log(logging.DEBUG)
        logger.debug('[INIT] set logging level: {}'.format(logging.getLogger().level))

        # args
        args = args_format()

        # prepare args
        mode = args.mode

        if mode == 'test':
            preprocess(args)


        t2 = time.time()
        logger.info('[INIT] Done! Consume Time:{ct}s'.format(ct=t2 - t1))
    except KeyboardInterrupt:
        logger.warning("[+++ISHGARD+++] Keyboard Stop.")
        sys.exit(0)

    except Exception as e:
        exc_msg = traceback.format_exc()
        logger.warning('[+++ISHGARD+++] Exception:' + exc_msg)


if __name__ == '__main__':
    main()
