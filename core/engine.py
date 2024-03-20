
import os
import re
import asyncio
import traceback

from .rule import Rule

from utils.file import FileParseAll
from utils.log import logger


def scan_single(func_call, target_directory, single_rule, files=None, is_unconfirm=False,
                newcore_function_list=[]):
    try:
        return SingleRule(func_call, target_directory, single_rule, files, is_unconfirm,
                          newcore_function_list).process()
    except Exception:
        raise


def scan(func_call, target_directory, special_rules=None, files=None, is_unconfirm=False):
    r = Rule()
    rules = r.rules(special_rules)

    find_vulnerabilities = []

    def store(result):
        if result is not None and isinstance(result, list) is True:
            for res in result:
                res.file_path = res.file_path
                find_vulnerabilities.append(res)
        else:
            logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

    async def start_scan(func_call, target_directory, rule, files):
        result = scan_single(func_call, target_directory, rule, files, is_unconfirm)
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
    def __init__(self, func_call, target_directory, single_rule, files, is_unconfirm=False,
                 newcore_function_list=[]):
        self.func_call = func_call
        self.target_directory = target_directory
        self.sr = single_rule
        self.files = files
        self.lan = self.sr.language.lower()
        self.is_unconfirm = is_unconfirm
        # Single Rule Vulnerabilities
        self.rule_vulnerabilities = []

        # new core function list
        self.newcore_function_list = newcore_function_list

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
            logger.debug(
                '[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=self.sr.svid, line=": ".join(list(origin_vulnerability))))
            if origin_vulnerability == ():
                logger.debug(' > continue...')
                continue

            if origin_vulnerability[0] and origin_vulnerability[1] and origin_vulnerability[2]:
                try:
                    core = Core(self.func_call, self.target_directory, origin_vulnerability, self.sr, files=self.files, is_unconfirm=self.is_unconfirm)
                    datas = core.scan()

                    return [core, datas]

                except Exception:
                    raise
        return None


class Core(object):
    def __init__(self, func_call, target_directory, vulnerability_result, single_rule,
                 index=0, files=None, is_unconfirm=False):
        """
        Initialize
        :param: target_directory:
        :param: vulnerability_result:
        :param single_rule: rule class
        :param index: vulnerability index
        :param files: core file list
        """
        self.func_call = func_call
        self.data = []
        self.controlled_list = []

        self.target_directory = os.path.normpath(target_directory)

        self.file_path = vulnerability_result[0].strip()
        self.line_number = vulnerability_result[1]
        self.code_content = vulnerability_result[2]

        self.files = files

        self.rule_match = single_rule.match
        self.rule_match_mode = single_rule.match_mode
        self.vul_function = single_rule.vul_function
        self.cvi = single_rule.svid
        self.lan = single_rule.language.lower()
        self.single_rule = single_rule
        self.is_unconfirm = is_unconfirm


        self.method = None
        logger.debug("""[CVI-{cvi}] [VERIFY-VULNERABILITY] ({index})
        > File: `{file}:{line}`
        > Code: `{code}`""".format(
            cvi=single_rule.svid,
            index=index,
            file=self.file_path,
            line=self.line_number,
            code=self.code_content))

    def is_match_only_rule(self):
        """
        Whether only match the rules, do not parameter controllable processing
        :method: It is determined by judging whether the left and right sides of the regex_location are brackets
        :return: boolean
        """
        if self.rule_match_mode == 'regex-only-match':
            return True
        else:
            return False

    def is_annotation(self):
        """
        Is annotation
        :method: Judgment by matching comment symbols (skipped when self.is_match_only_rule condition is met)
               - PHP:  `#` `//` `\*` `*`
                    //asdfasdf
                    \*asdfasdf
                    #asdfasdf
                    *asdfasdf
               - Java:
        :return: boolean
        """
        match_result = re.findall(r"^(#|\\\*|\/\/)+", self.code_content)
        # Skip detection only on match
        if self.is_match_only_rule():
            return False
        else:
            return len(match_result) > 0


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
        if self.is_annotation():
            logger.debug("[RET] Annotation")
            return False, 'Annotation(注释)'

        params = self.is_controllable_param()

        # program slicing




    def is_controllable_param(self):
        """
        is controllable param
        :return:
        """
        params = None
        if self.single_rule is not None:
            params = self.single_rule.main(self.code_content)

        if params is None:
            logger.debug("[AST] Not matching variables...")

        for param_name in params:
            self.param_name = param_name
            logger.debug('[AST] Param: `{0}`'.format(param_name))

        return params


