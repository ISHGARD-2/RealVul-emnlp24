
import os
import re
import asyncio
import traceback

from .rule import Rule

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
        self.vulnerability_data = []

        logger.info("[!] Start scan [CVI-{sr_id}]".format(sr_id=self.sr.svid))

    def origin_results(self):
        logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=self.sr.match_mode))

        # grep
        match = self.sr.match

        try:
            if match:
                f = FileParseAll(self.files, self.target_directory, language=self.lan)
                result = f.grep(match)
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
        origin_results = self.origin_results()
        # exists result
        if origin_results == '' or origin_results is None:
            logger.debug('[CVI-{cvi}] [ORIGIN] NOT FOUND!'.format(cvi=self.sr.svid))
            return None

        origin_vulnerabilities = origin_results
        for index, origin_vulnerability in enumerate(origin_vulnerabilities):
            if origin_vulnerability == ():
                logger.debug(' > continue...')
                continue

            if origin_vulnerability[0] and origin_vulnerability[1] and origin_vulnerability[2]:
                core = Core(self.func_call, self.target_directory, origin_vulnerability, self.sr)
                vul_slice = core.scan(self.mode)
                if vul_slice:
                    self.vulnerability_data.append(vul_slice)

        return


class Core(object):
    def __init__(self, func_call, target_directory, vulnerability_result, single_rule):
        """
        Initialize
        :param: target_directory:
        :param: vulnerability_result:
        :param single_rule: rule class
        :param index: vulnerability index
        :param files: core file list
        """
        self.func_call = func_call

        self.target_directory = os.path.normpath(target_directory)

        self.file_path = vulnerability_result[0].strip()
        self.file_path = self.file_path[self.file_path.find('/')+1:]
        self.line_number = vulnerability_result[1]
        self.code_content = vulnerability_result[2]

        self.single_rule = single_rule


    def scan(self, mode):
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
        logger.debug("{line1}[CVI-{cvi}][SLICING]{line2}".format(cvi=self.single_rule.svid, line1='-'*30, line2='-'*30))
        logger.debug("""[CVI-{cvi}][SLICING] > File: `{file}:{line}` > Code: `{code}`""".format(
            cvi=self.single_rule.svid, file=self.file_path,
            line=self.line_number, code=self.code_content))
        for param_name in params:
            logger.debug('[AST] Param: `{0}`'.format(param_name))

        slice = Slicing(params, self.func_call, self.target_directory, self.file_path, self.code_content, self.line_number, self.single_rule)
        vul_slice = slice.main(mode)
        vul_output = self.single_rule.complete_slice_end(self.code_content)

        tmp = vul_slice.split(self.code_content)
        if len(tmp) == 1:
            logger.warning("[WARRNING]engine.Core.scan():  slice failed")
            exit()

        output = ""
        for i, s in enumerate(tmp):
            if i+1 ==len(tmp):
                output += vul_output + s
            elif i == 0:
                output += s
            else:
                output += self.code_content + s
        # logger.debug("[SLICING]\n{}\n".format(vul_slice))
        logger.debug("[CVI-{cvi}] [SLICING]reslut: \n{vul_slice}\n".format(cvi=self.single_rule.svid,vul_slice=output))
        return output



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


