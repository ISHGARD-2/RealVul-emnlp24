# -*- coding: utf-8 -*-

import os
import re
import asyncio
import traceback

from .rule import Rule
from .cast import CAST

from Kunlun_M import const
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
    r = Rule("php")
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

    # print
    # data = []
    # data2 = []
    # table = PrettyTable(
    #     ['#', 'CVI', 'Rule(ID/Name)', 'Lang/CVE-id', 'Target-File:Line-Number',
    #      'Commit(Author)', 'Source Code Content', 'Analysis'])

    # table.align = 'l'
    # trigger_rules = []
    # for idx, x in enumerate(find_vulnerabilities):
    #
    #     trigger = '{fp}:{ln}'.format(fp=x.file_path.replace(target_directory, ""), ln=x.line_number)
    #     commit = u'@{author}'.format(author=x.commit_author)
    #     try:
    #         code_content = x.code_content[:50].strip()
    #     except AttributeError as e:
    #         code_content = x.code_content.decode('utf-8')[:100].strip()
    #     row = [idx + 1, x.id, x.rule_name, x.language, trigger, commit,
    #            code_content.replace('\r\n', ' ').replace('\n', ' '), x.analysis]
    #     row2 = [idx + 1, x.chain]
    #
    #     is_unconfirm_result = False
    #     if "unconfirmed" in x.analysis.lower():
    #         is_unconfirm_result = True
    #
    #     # save to database
    #     sr = check_update_or_new_scanresult(scan_task_id=a_sid, cvi_id=x.id, language=x.language,
    #                                         vulfile_path=trigger, source_code=code_content.replace('\r\n', ' ').replace('\n', ' '),
    #                                         result_type=x.analysis, is_unconfirm=is_unconfirm_result, is_active=True)
    #     # sr = ScanResultTask(scan_task_id=a_sid, result_id=idx + 1, cvi_id=x.id, language=x.language,
    #     #                     vulfile_path=trigger, source_code=code_content.replace('\r\n', ' ').replace('\n', ' '),
    #     #                     result_type=x.analysis, is_unconfirm=is_unconfirm_result)
    #     #
    #     # sr.save()
    #
    #     # 如果返回false，那么说明漏洞存在，不添加新的
    #     if sr:
    #         for chain in x.chain:
    #             if type(chain) == tuple:
    #                 ResultFlow = get_resultflow_class(int(a_sid))
    #                 node_source = show_context(chain[2], chain[3], is_back=True)
    #
    #                 rf = ResultFlow(vul_id=sr.id, node_type=chain[0], node_content=chain[1],
    #                                 node_path=chain[2], node_source=node_source, node_lineno=chain[3])
    #                 rf.save()
    #
    #     data.append(row)
    #     data2.append(row2)

        # table.add_row(row)

    #     if x.id not in trigger_rules:
    #         logger.debug(' > trigger rule (CVI-{cvi})'.format(cvi=x.id))
    #         trigger_rules.append(x.id)
    #
    #     # clear
    #     x.chain = ""
    #
    # diff_rules = list(set(push_rules) - set(trigger_rules))
    # vn = len(find_vulnerabilities)
    # if vn == 0:
    #     logger.info('[SCAN] Not found vulnerability!')
    # else:
    #     logger.info("[SCAN] Trigger Rules: {tr} Vulnerabilities ({vn})\r\n{table}".format(tr=len(trigger_rules),
    #                                                                                       vn=len(find_vulnerabilities),
    #                                                                                       table=table))
    #
    #     # 输出chain for all
    #     logger.info("[SCAN] Vulnerabilities Chain list: ")
    #     for d in data2:
    #         logger.info("[SCAN] Vul {}".format(d[0]))
    #         for c in d[1]:
    #             logger.info("[Chain] {}".format(c))
    #             if type(c) is not tuple and not c[3] is None and not re.match('^[0-9]+$', c[3]):
    #                 continue
    #             show_context(c[2], c[3])
    #
    #         logger.info("[SCAN] ending\r\n" + '-' * (shutil.get_terminal_size().columns - 16))
    #
    #     if len(diff_rules) > 0:
    #         logger.info(
    #             '[SCAN] Not Trigger Rules ({l}): {r}'.format(l=len(diff_rules), r=','.join(diff_rules)))
    #
    # # show detail about newcore function list
    # table2 = PrettyTable(
    #     ['#', 'NewFunction', 'OriginFunction', 'Related Rules id'])
    #
    # table2.align = 'l'
    # idy = 0
    # for new_function_name in newcore_function_list:
    #     # add new evil func in database
    #     for svid in newcore_function_list[new_function_name]["svid"]:
    #         if new_function_name and newcore_function_list[new_function_name]["origin_func_name"]:
    #
    #             nf = NewEvilFunc(svid=svid, scan_task_id=get_scan_id(), func_name=new_function_name,
    #                              origin_func_name=newcore_function_list[new_function_name]["origin_func_name"])
    #             nf.save()
    #
    #     table2.add_row([idy + 1, new_function_name, newcore_function_list[new_function_name]["origin_func_name"], newcore_function_list[new_function_name]["svid"]])
    #     idy += 1
    #
    # if len(newcore_function_list) > 0:
    #     logger.info("[SCAN] New evil Function list by NewCore:\r\n{}".format(table2))

    # completed running data
    # if s_sid is not None:
    #     Running(s_sid).data({
    #         'code': 1001,
    #         'msg': 'scan finished',
    #         'result': {
    #             'vulnerabilities': [x.__dict__ for x in find_vulnerabilities],
    #             'language': ",".join(language),
    #             'framework': framework,
    #             'extension': extension_count,
    #             'file': file_count,
    #             'push_rules': len(rules),
    #             #'trigger_rules': len(trigger_rules),
    #             'target_directory': target_directory
    #         }
    #     })
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
        if self.sr.match_mode == const.mm_regex_param_controllable:
            # 自定义匹配，调用脚本中的匹配函数匹配参数
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

        try:

            # organize information about vulnerability
            ast = CAST(self.func_call, self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule, controlled_params=self.controlled_list)

            # vustomize-match
            param_is_controllable, code, data, chain = ast.is_controllable_param()

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, 'Exception'


