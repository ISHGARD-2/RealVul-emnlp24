#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    core
    ~~~~~

    Implements core main

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import sys
import time
import argparse
import logging
import traceback

#from django.core.management import call_command
import logging
import argparse

from utils.utils import get_mainstr_from_filename, random_generator
from utils.status import get_scan_id


from . import cli
from .engine import Running


from core.rule import RuleCheck, TamperCheck

# try:
#     reload(sys)
#     sys.setdefaultencoding('utf-8')
# except NameError as e:
#     pass


def main():
    try:
        # arg parse
        t1 = time.time()

        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logging.debug('[+++ISHGARD+++][INIT] set logging level: {}'.format(logging.getLogger().level))

        parser = argparse.ArgumentParser()

        parser.add_argument('-t', '--target', type=str, default='', help="target file")
        parser.add_argument('-r', '--rule', type=int, default=None, help="vulnerability rule")

        args = parser.parse_args()

        #load vulnerability rules
        rule = args.rule
        logging.info("[INIT] RuleCheck start.")
        RuleCheck().load(rule)


        if not hasattr(args, "target") or args.target == '':
            parser.print_help()
            exit()

        logging.debug('[INIT] start Scan Task...')

        # 标识任务id
        task_name = str(args.target) + " rule_id: " + str(args.rule)
        task_id = hash(task_name)

        logging.info("TaskID: {}".format(task_id))

        logging.info("[INIT] New Log file ScanTask_{}.log .".format(task_id))
        log_name = "ScanTask_{}".format(task_id)

        data = {
            'status': 'running',
            'report': ''
        }
        Running(task_id).status(data)

        cli.start(args.target, args.format, args.output, args.special_rules, task_id, args.language, args.tamper_name, args.black_path, args.unconfirm, args.unprecom)

        t2 = time.time()

        logging.info('[INIT] Done! Consume Time:{ct}s'.format(ct=t2 - t1))

    except KeyboardInterrupt:
        logging.warning("[+++ISHGARD+++] Keyboard Stop.")
        sys.exit(0)

    except Exception as e:
        exc_msg = traceback.format_exc()
        logging.warning('[+++ISHGARD+++] Exception:'+exc_msg)


if __name__ == '__main__':
    main()