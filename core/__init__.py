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

# from django.core.management import call_command

import argparse
from utils.log import log, logger, log_add, log_rm

from utils.utils import get_mainstr_from_filename, random_generator
# from utils.status import get_scan_id

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

        # log
        log(logging.INFO)
        logger.debug('[INIT] set logging level: {}'.format(logging.getLogger().level))

        parser = argparse.ArgumentParser()

        parser.add_argument('-t', '--target', dest='target', type=str, default='', help="target file")
        parser.add_argument('-r', '--rule', dest='rule', type=str, default=None, help="vulnerability rule")

        args = parser.parse_args()

        # load vulnerability rules
        # rule = args.rule
        # logger.info("[INIT] RuleCheck start.")
        # RuleCheck().load(rule)

        if not hasattr(args, "target") or args.target == '':
            parser.print_help()
            exit()

        logger.debug('[INIT] start Scan Task...')

        # 标识任务id
        task_name = str(args.target) + " rule_id: " + str(args.rule)
        task_id = hash(task_name) % 10000

        logger.info("TaskID: {}".format(task_id))

        logger.info("[INIT] New Log file ScanTask_{}.log .".format(task_id))
        log_name = "ScanTask_{}".format(task_id)

        data = {
            'status': 'running',
            'report': ''
        }
        Running(task_id).status(data)

        cli.start(args.target, args.rule, a_sid=task_id)

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
