
import hashlib
import os
import random
import re
import string
import sys
import time
import ast
import zipfile

from configs.settings import RULES_PATH

from utils.log import logger
from utils.file import un_zip

TARGET_MODE_FILE = 'file'
TARGET_MODE_FOLDER = 'folder'


class ParseArgs(object):
    def __init__(self, target, formatter, output, special_rules=None, a_sid=None):
        self.target = target
        self.formatter = formatter
        self.output = output if output else ""
        self.language = ['php']
        logger.info("[INIT][PARSE_ARGS] Only one Language {}.".format(self.language))
        self.sid = a_sid

        if special_rules != None and special_rules != '':
            self.special_rules = []
            extension = '.py'
            start_name = 'CVI_'

            if ',' in special_rules:
                # check rule name
                s_rules = special_rules.split(',')
                for sr in s_rules:
                    if extension not in sr:
                        sr += extension
                    if start_name not in sr:
                        sr = start_name + sr

                    if self._check_rule_name(sr):
                        self.special_rules.append(sr)
                    else:
                        logger.critical('[PARSE-ARGS] Rule {sr} not exist'.format(sr=sr))
            else:
                special_rules = start_name + special_rules + extension

                if self._check_rule_name(special_rules):
                    self.special_rules = [special_rules]
                else:
                    logger.critical(
                        '[PARSE-ARGS] Exception special rule name(e.g: CVI-110001): {sr}'.format(sr=special_rules))
        else:
            self.special_rules = None


    @staticmethod
    def _check_rule_name(name):
        paths = os.listdir(RULES_PATH)

        for p in paths:
            try:
                if name in os.listdir(RULES_PATH + "/" + p):
                    return True
            except:
                continue

        return False


    @property
    def target_mode(self):
        """
        Parse target mode (git/file/folder/compress)
        :return: str
        """
        target_mode = None

        if os.path.isfile(self.target):
            target_mode = TARGET_MODE_FILE
        if os.path.isdir(self.target):
            target_mode = TARGET_MODE_FOLDER
        if target_mode is None:
            logger.critical('[PARSE-ARGS] [-t <target>] can\'t empty!')
            exit()
        logger.debug('[PARSE-ARGS] Target Mode: {mode}'.format(mode=target_mode))
        return target_mode


    def target_directory(self, target_mode):
        target_directory = None
        if target_mode == TARGET_MODE_FOLDER:
            target_directory = self.target
        elif target_mode == TARGET_MODE_FILE:
            target_directory = self.target

            # 检查目标是否为zip
            if os.path.splitext(target_directory)[-1] == '.zip':
                try:
                    logger.info("[CLI] Target {} is zip, try to unzip.".format(target_directory))
                    target_directory = un_zip(target_directory)

                except zipfile.BadZipFile:
                    logger.warning("[CLI] file {} not zip".format(target_directory))

                except OSError:
                    logger.warning("[CLI] file {} unzip error".format(target_directory))

            return target_directory
        else:
            logger.critical('[PARSE-ARGS] exception target mode ({mode})'.format(mode=target_mode))
            exit()

        logger.debug('[PARSE-ARGS] target directory: {directory}'.format(directory=target_directory))
        target_directory = os.path.abspath(target_directory)
        if target_directory[-1] == '/':
            return target_directory
        else:
            return u'{t}/'.format(t=target_directory)
