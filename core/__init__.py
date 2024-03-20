import sys
import time
import logging
import traceback

import argparse

from utils.file import Directory
from utils.log import log, logger
from utils.utils import ParseArgs

from core.preprocess.func_call import FuncCall
from core.preprocess.engine import scan


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
    args = parser.parse_args()

    if not hasattr(args, "target") or args.target == '':
        parser.print_help()
        exit()
    logger.debug('[INIT] start Scan Task...')

    return args


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
        pa, target_directory, files = args_prepare(args)

        # generate function call relationship
        func_call = FuncCall(target_directory, files)
        func_call.function_call_collection()

        # scan
        origin_vulns = scan(func_call, target_directory=target_directory, special_rules=pa.special_rules, files=files)

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
