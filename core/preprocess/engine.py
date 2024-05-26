import json
import os
import re
import asyncio
import traceback

from phply.phplex import lexer
from phply.phpparse import make_parser

from utils.func_json import write_json
from utils.utils import match_params
from .rule import Rule
from configs.settings import DATA_PATH, MAX_SLICE_LENGTH
from utils.file import FileParseAll
from utils.log import logger
from .slicing import Slicing


def scan_single(func_call, target_directory, single_rule, mode, files=None, is_unconfirm=False):
    try:
        return SingleRule(func_call, target_directory, single_rule, mode, files, is_unconfirm).process()
    except Exception:
        raise


def scan(func_call, target_directory, store_path, special_rules=None, files=None, mode="test"):
    r = Rule()
    rules = r.rules(special_rules)

    def start_scan(func_call, target_directory, rule, files, store_path):
        result = scan_single(func_call, target_directory, rule, mode, files)

        if store_path != None:
            write_json(result, store_path)

        return result

    if len(rules) == 0:
        logger.critical('no rules!')
        return False
    logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))

    results = {}
    for idx, single_rule in enumerate(sorted(rules.keys())):

        # init rule class
        r = getattr(rules[single_rule], single_rule)
        rule = r()

        if rule.status is False and len(rules) != 1:
            logger.info('[CVI_{cvi}] [STATUS] OFF, CONTINUE...'.format(cvi=rule.svid))
            continue
        # SR(Single Rule)
        logger.debug("""[PUSH] [CVI_{cvi}] {vulnerability}""".format(
            cvi=rule.svid,
            vulnerability=rule.vulnerability,
        ))
        # result = scan_single(target_directory, rule, files, language, tamper_name)
        if store_path != None:
            store_path = os.path.join(store_path, single_rule+'_dataset.json')
        result = start_scan(func_call, target_directory, rule, files, store_path)
        # store(result)
        results[rule.svid] = result

    return results


class SingleRule(object):
    def __init__(self, func_call, target_directory, single_rule, mode, files, is_unconfirm=False):
        self.func_call = func_call
        self.target_directory = target_directory
        self.sr = single_rule
        self.files = files
        self.mode = mode
        self.lan = self.sr.language.lower()
        self.is_unconfirm = is_unconfirm
        # Single Rule Vulnerabilities

        # process
        self.rule_id = self.sr.__class__.__name__
        self.rule_data_path = os.path.join(DATA_PATH, self.rule_id)
        if os.path.isdir(self.rule_data_path) is not True:
            os.mkdir(self.rule_data_path)

        self.slices = []

        logger.info("[!] Start scan [CVI-{sr_id}]".format(sr_id=self.sr.svid))

    def origin_results(self):
        logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=self.sr.match_mode))

        # grep
        match = self.sr.match

        try:
            if match:
                f = self.func_call.pfa
                result = f.grep(match, self.func_call.file_list)
            else:
                result = None
        except Exception as e:
            traceback.print_exc()
            logger.debug('match exception ({e})'.format(e=e))
            return None

        try:
            result = result.decode('utf-8')
        except AttributeError as e:
            pass

        return result

    def process(self):
        """
        Process Single Rule
        :return: SRV(Single Rule Vulnerabilities)
        """
        origin_vulnerabilities = self.origin_results()
        # exists result
        if origin_vulnerabilities == '' or origin_vulnerabilities is None:
            logger.debug('[CVI-{cvi}] [ORIGIN] NOT FOUND!'.format(cvi=self.sr.svid))
            return None

        for index, origin_vulnerability in enumerate(origin_vulnerabilities):
            if origin_vulnerability == ():
                logger.debug(' > continue...')
                continue

            if origin_vulnerability[0] and origin_vulnerability[1] and origin_vulnerability[2]:
                core = Core(self.func_call, self.target_directory, origin_vulnerability, self.sr, self.mode)
                vul_slice = core.scan()
                if vul_slice:
                    if self.mode == 'test' or 'synthesis':
                        for s in vul_slice:
                            self.save_test_samples(s, origin_vulnerability[0])


        return self.slices

    def save_test_samples(self, slice, file_path):
        """
        in test mode:
        save code slices to ./data/{cvi-id}/
        """
        id = len(self.slices)
        file_name = file_path
        if file_name.startswith('good'):
            slice_label = 'good'
        else:
            slice_label = 'bad'

        content = {'slice': slice,
                   'id':id,
                   'slice_label': slice_label,
                   'file_name': file_name,
                   'rule': self.rule_id,
                   'label':'',
                   'message':'',
                   }
        if self.mode == 'synthesis':
            if 'SARD' in file_name:
                raw_dataset = 'SARD'
                raw_sample_id = file_name.split(raw_dataset)[1].split('__')[2]
            elif 'crossvul' in file_name:
                raw_dataset = 'crossvul'
                raw_sample_id = file_name.split(raw_dataset)[1].split('__')[2]
                raw_sample_id = raw_sample_id.split('_')[1]
            else:
                raise Exception
            label = file_name.split(raw_dataset)[1].split('__')[1]
            CVE_database_id = file_name.split('__')[0].split('_')[1]

            content['label'] = label
            content['message'] = 'synthesis'
            content['raw_sample_id'] = int(raw_sample_id)
            content['CVE_database_id'] = int(CVE_database_id)

        elif self.mode == 'test':
            CVE_database_id = file_path.split('_')[1]
            content['CVE_database_id'] = CVE_database_id

        self.slices.append(content)


class Core(object):
    def __init__(self, func_call, target_directory, vulnerability_result, single_rule, mode="test"):
        """
        Initialize
        :param: target_directory:
        :param: vulnerability_result:
        :param single_rule: rule class
        :param index: vulnerability index
        :param files: core file list
        :mode   test: for LLM
                scan: for common project
        """
        self.func_call = func_call

        self.target_directory = os.path.normpath(target_directory)

        self.file_path = vulnerability_result[0]
        self.line_number = vulnerability_result[1]
        self.code_content = vulnerability_result[2]

        self.single_rule = single_rule
        self.mode = mode

    def scan(self):
        """
        Scan vulnerabilities
        :flow:
        - whitelist file
        - special file
        - test file
        - annotation
        - rule
        :return: is_vulnerability, code
        """

        params = self.get_stmt_param()

        if not params:
            return None
        params = list(set(params))
        # program slicing

        if self.mode != 'synthesis':
            logger.debug(
                "{line1}[CVI-{cvi}][SLICING]{line2}".format(cvi=self.single_rule.svid, line1='-' * 30, line2='-' * 30))
            logger.debug("""[CVI-{cvi}][SLICING] > File: `{file}:{line}` > Code: `{code}`""".format(
                cvi=self.single_rule.svid, file=self.file_path,
                line=self.line_number, code=self.code_content))

        output_list=[]
        for param_name in params:
            if self.mode != 'synthesis':
                logger.debug('[AST] Param: `{0}`'.format(param_name))

            para = {'name':param_name, 'lineno':int(self.line_number)}
            # make slice here
            slice = Slicing([para], self.func_call, self.target_directory, self.file_path, self.code_content,
                            self.line_number, self.single_rule)
            vul_slice = slice.main(self.mode)


            if not vul_slice :
                return None


            output = self.single_rule.complete_slice_end(vul_slice, self.code_content, para)

            if output:
                #logger.debug("[SLICING]\n{}\n".format(vul_slice))
                if self.mode != 'synthesis':
                    logger.debug("[CVI-{cvi}] [SLICING]result: \n{vul_slice}\n".format(cvi=self.single_rule.svid, vul_slice=output))
                output_list.append(output)
        return output_list



    def get_stmt_param(self):
        """
        is controllable param
        :return:
        """
        params = None
        if self.single_rule is not None:
            params = match_params(self.code_content)

        if params is None:
            logger.debug("[AST] Not matching variables...")

        return params
