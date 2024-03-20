# -*- coding: utf-8 -*-

import os
import re
import traceback
from utils.log import logger


class CAST(object):
    languages = {'php': "php",
                 'java': "java",
                 'sol': "sol",
                 'js': "javascript"}

    def __init__(self,func_call, rule, target_directory, file_path, line, code, files=None, rule_class=None, controlled_params=[]):
        self.func_call = func_call
        self.target_directory = target_directory
        self.data = []
        self.rule = rule
        self.file_path = file_path
        self.line = line
        self.code = code
        self.files = files
        self.param_name = None
        self.param_value = None
        self.language = None
        self.sr = rule_class

        for language in self.languages:
            if self.file_path[-len(language):].lower() == language:
                self.language = self.languages[language]

        if os.path.isdir(self.target_directory):
            os.chdir(self.target_directory)
        # Parse rule
        self.regex = {
            'php': {
                'functions': r'(?:function\s+)(\w+)\s*\(',
                'string': r"(?:['\"])(.*)(?:[\"'])",
                'assign_string': r"({0}\s?=\s?[\"'](.*)(?:['\"]))",
                'annotation': r"(#|\\\*|\/\/|\*)+",
                'variable': r'(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)',
                'assign_out_input': r'({0}\s?=\s?.*\$_[GET|POST|REQUEST|SERVER|COOKIE]+(?:\[))'
            }
        }
        logger.debug("[AST] [LANGUAGE] {language}".format(language=self.language))


    def is_controllable_param(self):
        """
        is controllable param
        :return:
        """
        params = None
        if self.sr is not None:
            params = self.sr.main(self.code)

        if params is None:
            logger.debug("[AST] Not matching variables...")

        for param_name in params:
            self.param_name = param_name
            logger.debug('[AST] Param: `{0}`'.format(param_name))

        return params


