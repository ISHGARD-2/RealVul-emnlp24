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
        self.controlled_list = controlled_params

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
            return False, -1, self.data, []

        for param_name in params:
            try:
                self.param_name = param_name
                logger.debug('[AST] Param: `{0}`'.format(param_name))

                # all is string
                regex_string = self.regex[self.language]['string']
                string = re.findall(regex_string, param_name)
                if len(string) >= 1 and string[0] != '':
                    regex_get_variable_result = re.findall(self.regex[self.language]['variable'], param_name)
                    len_regex_get_variable_result = len(regex_get_variable_result)
                    if len_regex_get_variable_result >= 1:
                        # TODO
                        # 'ping $v1 $v2'
                        # foreach $vn
                        param_name = regex_get_variable_result[0]
                        logger.info("[AST] String's variables: `{variables}`".format(
                            variables=','.join(regex_get_variable_result)))
                    else:
                        logger.debug("[AST] String have variables: `No`")
                        return False, -1, self.data, []
                logger.debug("[AST] String have variables: `Yes`")
            except KeyboardInterrupt as e:
                raise
            except:
                logger.warning(
                    "[AST] Can't get `param`, check built-in rule..error details:\n{}".format(traceback.format_exc()))
                return False, -1, self.data, []


        # variable


        return False, self.data, None, None


