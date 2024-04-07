import json
import os
import re
import asyncio
import traceback

from phply.phplex import lexer
from phply.phpparse import make_parser

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


def scan(func_call, target_directory, special_rules=None, files=None, mode="test"):
    r = Rule()
    rules = r.rules(special_rules)

    find_vulnerabilities = []

    def store(result):
        # if result is not None and isinstance(result, list) is True:
        #     for res in result:
        #         res.file_path = res.file_path
        #         find_vulnerabilities.append(res)
        # else:
        #     logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')
        return

    async def start_scan(func_call, target_directory, rule, files):
        result = scan_single(func_call, target_directory, rule, mode, files)
        store(result)

    if len(rules) == 0:
        logger.critical('no rules!')
        return False
    logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))
    push_rules = []
    scan_list = []

    for idx, single_rule in enumerate(sorted(rules.keys())):

        # init rule class
        r = getattr(rules[single_rule], single_rule)
        rule = r()

        if rule.status is False and len(rules) != 1:
            logger.info('[CVI_{cvi}] [STATUS] OFF, CONTINUE...'.format(cvi=rule.svid))
            continue
        # SR(Single Rule)
        logger.debug("""[PUSH] [CVI_{cvi}] {idx}.{vulnerability}({language})""".format(
            cvi=rule.svid,
            idx=idx,
            vulnerability=rule.vulnerability,
            language=rule.language
        ))
        # result = scan_single(target_directory, rule, files, language, tamper_name)
        scan_list.append(start_scan(func_call, target_directory, rule, files))
        # store(result)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(*scan_list))

    loop.stop()

    return True


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
        self.rule_data_path = DATA_PATH + '/' + self.rule_id
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
                    if self.mode == 'test':
                        self.save_test_samples(vul_slice, origin_vulnerability[0])

        slices = json.dumps(self.slices)
        f = open(self.rule_data_path + '/dataset_raw4.json', 'w')
        f.write(slices)
        f.close()
        return

    def save_test_samples(self, slice, file_path):
        """
        in test mode:
        save code slices to ./data/{cvi-id}/
        """
        id = len(self.slices)
        file_name = file_path.split('/')[-1]
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
                   'message':''}
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

        self.file_path = vulnerability_result[0].strip()
        self.file_path = self.file_path[self.file_path.find('/') + 1:]
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

        # program slicing
        logger.debug(
            "{line1}[CVI-{cvi}][SLICING]{line2}".format(cvi=self.single_rule.svid, line1='-' * 30, line2='-' * 30))
        logger.debug("""[CVI-{cvi}][SLICING] > File: `{file}:{line}` > Code: `{code}`""".format(
            cvi=self.single_rule.svid, file=self.file_path,
            line=self.line_number, code=self.code_content))
        for param_name in params:
            logger.debug('[AST] Param: `{0}`'.format(param_name))

        slice = Slicing(params, self.func_call, self.target_directory, self.file_path, self.code_content,
                        self.line_number, self.single_rule)
        vul_slice = slice.main(self.mode)


        if not vul_slice or len(vul_slice) > MAX_SLICE_LENGTH:
            logger.debug('[SLICE] slice too long\n')
            return None

        slilce_check = self.slilce_check_syntax(vul_slice)

        if not slilce_check or self.code_content not in vul_slice:
            return None

        vul_output = self.single_rule.complete_slice_end(self.code_content)

        tmp = vul_slice.split(self.code_content)
        # if len(tmp) == 1 and len(tmp[0].strip()) > 2:
        #     logger.warning("[WARRNING]engine.Core.scan():  slice failed")
        #     return None

        output = ""
        for i, s in enumerate(tmp):
            if i == 0 and len(tmp) > 1:
                output += s
            elif i + 1 == len(tmp):
                output += vul_output + s
            elif i == 0 and len(tmp) == 1:
                output += s + vul_output
            else:
                output += self.code_content + s
        # logger.debug("[SLICING]\n{}\n".format(vul_slice))
        logger.debug("[CVI-{cvi}] [SLICING]reslut: \n{vul_slice}\n".format(cvi=self.single_rule.svid, vul_slice=output))
        return output

    def slilce_check_syntax(self, code):

        try:
            parser = make_parser()
            all_nodes = parser.parse(code, debug=False, lexer=lexer.clone(), tracking=True)

        except SyntaxError as e:
            logger.warning('[SLICE] slice syntax error\n')
            return False

        except AssertionError as e:
            logger.warning('[SLICE] slice error\n')
            return False

        except:
            logger.warning('[SLICE] slice error\n')
            return False
        return True

    def get_stmt_param(self):
        """
        is controllable param
        :return:
        """
        params = None
        if self.single_rule is not None:
            params = self.single_rule.main(self.code_content)

        if params is None:
            logger.debug("[AST] Not matching variables...")

        return params
