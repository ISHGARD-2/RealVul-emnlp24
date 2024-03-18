import asyncio

from Kunlun_M import const
from Kunlun_M.const import VulnerabilityResult
from core.rule import Rule
from utils.file import FileParseAll
from utils.log import logger
import re


class ProgramSlicing():
    def __init__(self):
        self.CFG = {"nodes":[], "code":""}

    def slicing(self, function_list):
        for func in function_list:
            self.slicing_one(func)

    def slicing_one(self, function, target_directory, a_sid=None, s_sid=None, special_rules=None, language=None, framework=None, file_count=0,
         extension_count=0, files=None, tamper_name=None, is_unconfirm=False):

        def store(result):
            if result is not None and isinstance(result, list) is True:
                for res in result:
                    res.file_path = res.file_path
                    find_vulnerabilities.append(res)
            else:
                logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

        async def start_scan(func_call, target_directory, rule, files, language, tamper_name):
            result = scan_single(func_call, target_directory, rule, files, language, tamper_name, is_unconfirm)
            store(result)

        r = Rule(language)
        rules = r.rules(special_rules)

        find_vulnerabilities = []
        if len(rules) == 0:
            logger.critical('no rules!')
            return False
        logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))
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
            scan_list.append(start_scan(function, target_directory, rule, files, language, tamper_name))
            # store(result)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(asyncio.gather(*scan_list))

        loop.stop()

    def scan_single(self, function, target_directory, single_rule, files=None, language=None, tamper_name=None,
                    is_unconfirm=False,
                    newcore_function_list=[]):
        try:
            return SingleRule(self, function, target_directory, single_rule, files, language, tamper_name, is_unconfirm,
                              newcore_function_list).process()
        except Exception:
            raise

class SingleRule(object):
    def __init__(self, function, target_directory, single_rule, files, language=None, tamper_name=None, is_unconfirm=False,
                 newcore_function_list=[]):
        self.function = function
        self.target_directory = target_directory
        self.sr = single_rule
        self.files = files
        self.languages = language
        self.lan = self.sr.language.lower()
        self.tamper_name = tamper_name
        self.is_unconfirm = is_unconfirm
        # Single Rule Vulnerabilities
        """
        [
            vr
        ]
        """
        self.rule_vulnerabilities = []

        # new core function list
        self.newcore_function_list = newcore_function_list

        logger.info("[!] Start scan [CVI-{sr_id}]".format(sr_id=self.sr.svid))

    def origin_results(self):
        logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=self.sr.match_mode))

        # grep
        if self.sr.match_mode == const.mm_regex_only_match:
            # 当所有match都满足时成立，当单一unmatch满足时，不成立
            matchs = self.sr.match
            unmatchs = self.sr.unmatch
            result = []
            new_result = []
            old_result = 0

            try:
                if matchs:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)

                    for match in matchs:

                        new_result = f.multi_grep(match)

                        if old_result == 0:
                            old_result = new_result
                            result = new_result
                            continue

                        old_result = result
                        result = []

                        for old_vul in old_result:
                            for new_vul in new_result:
                                if new_vul[0] == old_vul[0]:
                                    result.append(old_vul)

                    for unmatch in unmatchs:
                        uresults = f.multi_grep(unmatch)

                        for uresult in uresults:
                            for vul in result:
                                if vul[0] == uresult[0]:
                                    result.remove(vul)

                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                return None

        elif self.sr.match_mode == const.mm_regex_param_controllable:
            # 自定义匹配，调用脚本中的匹配函数匹配参数
            match = self.sr.match

            try:
                if match:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)
                    result = f.grep(match)
                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                return None

        elif self.sr.match_mode == const.mm_function_param_controllable:
            # 函数匹配，直接匹配敏感函数，然后处理敏感函数的参数即可
            # param controllable
            if '|' in self.sr.match:
                match = const.fpc_multi.replace('[f]', self.sr.match)
                if self.sr.keyword == 'is_echo_statement':
                    match = const.fpc_echo_statement_multi.replace('[f]', self.sr.match)
            else:
                match = const.fpc_single.replace('[f]', self.sr.match)
                if self.sr.keyword == 'is_echo_statement':
                    match = const.fpc_echo_statement_single.replace('[f]', self.sr.match)

            try:
                if match:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)
                    result = f.grep(match)

                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                return None

        elif self.sr.match_mode == const.mm_regex_return_regex:
            # 回馈式正则匹配，将匹配到的内容返回，然后合入正则表达式

            matchs = self.sr.match
            unmatchs = self.sr.unmatch
            matchs_name = self.sr.match_name
            black_list = self.sr.black_list

            result = []

            try:
                f = FileParseAll(self.files, self.target_directory, language=self.lan)

                result = f.multi_grep_name(matchs, unmatchs, matchs_name, black_list)
                if not result:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                return None
        else:
            logger.warning('Exception match mode: {m}'.format(m=self.sr.match_mode))
            result = None

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
            vulnerability = self.parse_match(origin_vulnerability)
            if vulnerability is None:
                logger.debug('Not vulnerability, continue...')
                continue
            is_test = False

            try:
                datas = Core(self.func_call, self.target_directory, vulnerability, self.sr, 'project name',
                             ['whitelist1', 'whitelist2'], test=is_test, index=index,
                             files=self.files, languages=self.languages, tamper_name=self.tamper_name,
                             is_unconfirm=self.is_unconfirm).scan()

                data = ""

                if len(datas) == 3:
                    is_vulnerability, reason, data = datas

                    if "New Core" not in reason:
                        code = "Code: {}".format(origin_vulnerability[2].strip(" "))
                        file_path = os.path.normpath(origin_vulnerability[0])
                        data.insert(1, ("NewScan", code, origin_vulnerability[0], origin_vulnerability[1]))

                elif len(datas) == 2:
                    is_vulnerability, reason = datas
                else:
                    is_vulnerability, reason = False, "Unpack error"

                if is_vulnerability:
                    logger.debug('[CVI-{cvi}] [RET] Found {code}'.format(cvi=self.sr.svid, code=reason))
                    vulnerability.analysis = reason
                    vulnerability.chain = data
                    self.rule_vulnerabilities.append(vulnerability)
                else:
                    if reason == 'New Core':  # 新的规则

                        logger.debug('[CVI-{cvi}] [NEW-VUL] New Rules init'.format(cvi=self.sr.svid))
                        new_rule_vulnerabilities = NewCore(self.sr, self.target_directory, data, self.files, 0,
                                                           languages=self.languages, tamper_name=self.tamper_name,
                                                           is_unconfirm=self.is_unconfirm,
                                                           newcore_function_list=self.newcore_function_list)

                        if len(new_rule_vulnerabilities) > 0:
                            self.rule_vulnerabilities.extend(new_rule_vulnerabilities)

                    else:
                        logger.debug('Not vulnerability: {code}'.format(code=reason))
            except Exception:
                raise
        logger.debug('[CVI-{cvi}] {vn} Vulnerabilities: {count}'.format(cvi=self.sr.svid, vn=self.sr.vulnerability,
                                                                        count=len(self.rule_vulnerabilities)))
        return self.rule_vulnerabilities

    def parse_match(self, single_match):
        mr = VulnerabilityResult()
        # grep result
        #
        # Rules
        #
        # (u'D:\\program\\core-w\\tests\\vulnerabilities/v.php', 10, 'echo($callback . ";");\n')
        try:
            mr.line_number = single_match[1]
            mr.code_content = single_match[2]
            mr.file_path = single_match[0]
        except Exception:
            logger.warning('[ENGINE] match line parse exception')
            mr.file_path = ''
            mr.code_content = ''
            mr.line_number = 0

        # vulnerability information
        mr.rule_name = self.sr.vulnerability
        mr.id = self.sr.svid
        mr.language = self.sr.language
        mr.commit_author = self.sr.author

        return mr


def origin_vulnerability_grep(function, reg):
    result = []

    line_number = 1
    i = 0
    content = ""

    # 逐行匹配问题比较大，先测试为每5行匹配一次
    for line in function["code"]:
        i += 1
        line_number += 1
        content += line

        if i < 10:
            continue

        content = check_comment(content)

        i = 0
        # print line, line_number
        if re.search(reg, content, re.I):

            # 尝试通过以目标作为标志分割，来判断行数
            # 目标以前的回车数计算
            p = re.compile(reg)
            matchs = p.finditer(content)

            for m in matchs:
                data = m.group(0).strip()

                split_data = content.split(data)[0]
                # enddata = content.split(data)[1]

                LRnumber = " ".join(split_data).count('\n')

                match_numer = line_number - 10 + LRnumber

                result.append((function, str(match_numer), data))

        content = ""

    content = check_comment(content)

    # 如果退出循环的时候没有清零，则还要检查一次
    if i > 0:
        if re.search(reg, content, re.I):
            # 尝试通过以目标作为标志分割，来判断行数
            # 目标以前的回车数计算
            p = re.compile(reg)
            matchs = p.finditer(content)

            for m in matchs:
                data = m.group(0).strip()

                split_data = content.split(data)[0]
                # enddata = content.split(data)[1]

                LRnumber = " ".join(split_data).count('\n')

                match_numer = line_number - i + LRnumber

                result.append((function, str(match_numer), data))

    return result

def check_comment(self, content):
    backstr = ""

    lastchar = ""
    isinlinecomment = False
    isduolinecomment = False

    for char in content:
        if char == '/' and lastchar == '/':
            backstr = backstr[:-1]
            isinlinecomment = True
            lastchar = ""
            continue

        if isinlinecomment:
            if char == '\n':
                isinlinecomment = False

                lastchar = ''
                backstr += '\n'
            continue


        if char == '\n':
            backstr += '\n'
            continue

        # 多行注释
        if char == '*' and lastchar == '/':
            isduolinecomment = True
            backstr = backstr[:-1]
            lastchar = ""
            continue

        if isduolinecomment:

            if char == '/' and lastchar == '*':
                isduolinecomment = False
                lastchar = ""
                continue

            lastchar = char
            continue

        lastchar = char
        backstr += char

    return backstr
