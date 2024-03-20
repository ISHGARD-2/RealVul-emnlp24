# -*- coding: utf-8 -*-

"""
    cli
    ~~~

    Implements CLI mode

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""

# import traceback
# from prettytable import PrettyTable
#
#
# from utils.log import logger
# from utils.file import Directory
# from utils.utils import show_context
# from utils.utils import ParseArgs, get_sid
# from utils.utils import md5, random_generator
# from core.vendors import get_project_by_version
# from Kunlun_M.const import VUL_LEVEL, VENDOR_VUL_LEVEL
#
# from web.index.models import ScanTask, Rules, NewEvilFunc, VendorVulns
# from web.index.models import get_resultflow_class, get_and_check_scantask_project_id, check_and_new_project_id, get_and_check_scanresult
#
#
# def check_scantask(task_name, target_path, parameter_config, project_origin, project_des="", auto_yes=False):
#     s = ScanTask.objects.filter(task_name=task_name, target_path=target_path, parameter_config=parameter_config, is_finished=1).order_by("-id").first()
#
#     if s and not auto_yes:
#         logger.warning("[INIT] ScanTask for {} has been executed.".format(task_name))
#         logger.warning("[INIT] whether rescan Task {}?(Y/N) (Default N)".format(task_name))
#
#         if input().lower() != 'y':
#             logger.warning("[INIT] whether Show Last Scan Result?(Y/N) (Default Y)")
#
#             if input().lower() != 'n':
#                 display_result(s.id, is_ask=True)
#         else:
#             s = ScanTask(task_name=task_name, target_path=target_path, parameter_config=parameter_config)
#             s.save()
#
#             # check and new project
#             check_and_new_project_id(scantask_id=s.id, task_name=task_name, project_origin=project_origin, project_des=project_des)
#
#     else:
#         s = ScanTask(task_name=task_name, target_path=target_path, parameter_config=parameter_config)
#         s.save()
#
#         # check and new project
#         check_and_new_project_id(s.id, task_name=task_name, project_origin=project_origin, project_des=project_des)
#
#     return s
#
#
# def display_result(scan_id, is_ask=False):
#
#     table = PrettyTable(
#         ['#', 'CVI', 'Rule(ID/Name)', 'Lang/CVE-id', 'Level', 'Target-File:Line-Number',
#          'Commit(Author)', 'Source Code Content', 'Analysis'])
#     table.align = 'l'
#
#     # check unconfirm
#     if is_ask:
#         logger.warning("[INIT] whether Show Unconfirm Result?(Y/N) (Default Y)")
#
#     project_id = get_and_check_scantask_project_id(scan_id)
#
#     if is_ask:
#         if input().lower() != 'n':
#             srs = get_and_check_scanresult(scan_id).objects.filter(scan_project_id=project_id, is_active=True)
#         else:
#             srs = get_and_check_scanresult(scan_id).objects.filter(scan_project_id=project_id, is_active=True,
#                                                                    is_unconfirm=False)
#     else:
#         srs = get_and_check_scanresult(scan_id).objects.filter(scan_project_id=project_id, is_active=True,
#                                                                is_unconfirm=False)
#     logger.info("[INIT] Project ID is {}".format(project_id))
#
#     if srs:
#         logger.info("[MainThread] Scan id {} Result: ".format(scan_id))
#
#         for sr in srs:
#
#             # for vendor scan
#             if sr.cvi_id == '9999':
#                 vendor_vuls_id = int(sr.vulfile_path.split(':')[-1])
#                 vv = VendorVulns.objects.filter(id=vendor_vuls_id).first()
#
#                 if vv:
#                     rule_name = vv.title
#                     author = 'SCA'
#                     level = VENDOR_VUL_LEVEL[int(vv.severity)]
#                     # sr.source_code = vv.description
#                 else:
#                     rule_name = 'SCA Scan'
#                     author = 'SCA'
#                     level = VENDOR_VUL_LEVEL[1]
#
#             else:
#                 rule = Rules.objects.filter(svid=sr.cvi_id).first()
#                 rule_name = rule.rule_name
#                 author = rule.author
#                 level = VUL_LEVEL[rule.level]
#
#             row = [sr.id, sr.cvi_id, rule_name, sr.language, level, sr.vulfile_path,
#                    author, sr.source_code, sr.result_type]
#
#             table.add_row(row)
#
#             # show Vuls Chain
#             ResultFlow = get_resultflow_class(scan_id)
#             rfs = ResultFlow.objects.filter(vul_id=sr.id)
#
#             logger.info("[Chain] Vul {}".format(sr.id))
#             for rf in rfs:
#                 logger.info("[Chain] {}, {}, {}:{}".format(rf.node_type, rf.node_content, rf.node_path, rf.node_lineno))
#
#                 try:
#                     if author == 'SCA':
#                         continue
#
#                     if not show_context(rf.node_path, rf.node_lineno):
#                         logger_console.info(rf.node_source)
#                 except:
#                     logger.error("[SCAN] Error: {}".format(traceback.print_exc()))
#                     continue
#
#             logger.info(
#                 "[SCAN] ending\r\n -------------------------------------------------------------------------")
#
#         logger.info("[SCAN] Trigger Vulnerabilities ({vn})\r\n{table}".format(vn=len(srs), table=table))
#
#         # show New evil Function
#         nfs = NewEvilFunc.objects.filter(project_id=project_id, is_active=1)
#
#         if nfs:
#
#             table2 = PrettyTable(
#                 ['#', 'NewFunction', 'OriginFunction', 'Related Rules id'])
#
#             table2.align = 'l'
#             idy = 1
#
#             for nf in nfs:
#                 row = [idy, nf.func_name, nf.origin_func_name, nf.svid]
#
#                 table2.add_row(row)
#                 idy += 1
#
#             logger.info("[MainThread] New evil Function list by NewCore:\r\n{table}".format(table=table2))
#
#     else:
#         logger.info("[MainThread] Scan id {} has no Result.".format(scan_id))
#
#
# # def start(func_call, pa, target, special_rules, formatter='csv', output='', a_sid=None, tamper_name=None, is_unconfirm=False, is_unprecom=False):
# #     """
# #     Start CLI
# #     :param black_path:
# #     :param tamper_name:
# #     :param language:
# #     :param target: File, FOLDER, GIT
# #     :param formatter:
# #     :param output:
# #     :param special_rules:
# #     :param a_sid: all scan id
# #     :return:
# #     # """
# #     s_sid = get_sid(target)
# #     target_mode = pa.target_mode
# #     black_path_list = pa.black_path_list
# #
# #     # target directory
# #     try:
# #         target_directory = pa.target_directory(target_mode)
# #
# #         # static analyse files info
# #         files, file_count, time_consume = Directory(target_directory, black_path_list).collect_files()
# #
# #         # detection main language and framework
# #         main_language = pa.language
# #         main_framework = pa.language
# #
# #         # scan
# #         scan(func_call, target_directory=target_directory, a_sid=a_sid, s_sid=s_sid, special_rules=pa.special_rules,
# #              language=main_language, framework=main_framework, file_count=file_count, extension_count=len(files),
# #              files=files, tamper_name=tamper_name, is_unconfirm=is_unconfirm)
# #
# #         # show result
# #         #display_result(task_id)
# #
# #     except KeyboardInterrupt as e:
# #         logger.error("[!] KeyboardInterrupt, exit...")
# #         exit()
# #     except Exception:
# #         result = {
# #             'code': 1002,
# #             'msg': 'Exception'
# #         }
# #         Running(s_sid).data(result)
# #         raise
# #
# #     # 输出写入文件
# #     write_to_file(target=target, sid=s_sid, output_format=formatter, filename=output)
# #
#
# # def show_info(type, key):
# #     """
# #     展示信息
# #     """
# #     def list_parse(rules_path, istamp=False):
# #
# #         files = os.listdir(rules_path)
# #         result = []
# #
# #         for f in files:
# #
# #             if f.startswith("_") or f.endswith("pyc"):
# #                 continue
# #
# #             if os.path.isdir(os.path.join(rules_path, f)):
# #                 if f not in ['test', 'tamper']:
# #                     result.append(f)
# #
# #             if f.startswith("CVI_"):
# #                 result.append(f)
# #
# #             if istamp:
# #                 if f not in ['test.py', 'demo.py', 'none.py']:
# #                     result.append(f)
# #
# #         return result
# #
# #     info_dict = {}
# #
# #     if type == "rule":
# #
# #         rule_lan_list = list_parse(RULES_PATH)
# #         rule_dict = {}
# #         if key == "all":
# #             # show all
# #             for lan in rule_lan_list:
# #                 info_dict[lan] = []
# #                 rule_lan_path = os.path.join(RULES_PATH, lan)
# #
# #                 info_dict[lan] = list_parse(rule_lan_path)
# #
# #         elif key in rule_lan_list:
# #             info_dict[key] = []
# #             rule_lan_path = os.path.join(RULES_PATH, key)
# #
# #             info_dict[key] = list_parse(rule_lan_path)
# #
# #         elif str(int(key)) == key:
# #             for lan in rule_lan_list:
# #                 info_dict[lan] = []
# #                 rule_lan_path = os.path.join(RULES_PATH, lan)
# #
# #                 info_dict[lan] = list_parse(rule_lan_path)
# #
# #             for lan in info_dict:
# #                 if "CVI_{}.py".format(key) in info_dict[lan]:
# #                     f = codecs.open(os.path.join(RULES_PATH, lan, "CVI_{}.py".format(key)), encoding='utf-8', errors="ignore")
# #                     return f.read()
# #
# #             logger.error('[Show] no CVI id {}.'.format(key))
# #             return ""
# #         else:
# #             logger.error('[Show] error language/CVI id input.')
# #             return ""
# #
# #         i = 0
# #         table = PrettyTable(
# #             ['#', 'CVI', 'Lang/CVE-id', 'Rule(ID/Name)', 'Match', 'Status'])
# #
# #         table.align = 'l'
# #
# #         for lan in info_dict:
# #             for rule in info_dict[lan]:
# #                 i += 1
# #                 rulename = rule.split('.')[0]
# #                 rulefile = "rules." + lan + "." + rulename
# #
# #                 rule_obj = __import__(rulefile, fromlist=rulename)
# #                 p = getattr(rule_obj, rulename)
# #
# #                 ruleclass = p()
# #
# #                 table.add_row([i, ruleclass.svid, ruleclass.language, ruleclass.vulnerability, ruleclass.match, ruleclass.status])
# #
# #         return table
# #
# #     elif type == "tamper":
# #
# #         table = PrettyTable(
# #             ['#', 'TampName', 'FilterFunc', 'InputControl'])
# #
# #         table.align = 'l'
# #         i = 0
# #
# #         tamp_path = os.path.join(RULES_PATH, 'tamper/')
# #         tamp_list = list_parse(tamp_path, True)
# #
# #         if key == "all":
# #             for tamp in tamp_list:
# #                 i += 1
# #                 tampname = tamp.split('.')[0]
# #                 tampfile = "rules.tamper." + tampname
# #
# #                 tamp_obj = __import__(tampfile, fromlist=tampname)
# #
# #                 filter_func = getattr(tamp_obj, tampname)
# #                 input_control = getattr(tamp_obj, tampname + "_controlled")
# #
# #                 table.add_row([i, tampname, filter_func, input_control])
# #
# #             return table
# #         elif key + ".py" in tamp_list:
# #             tampname = key
# #             tampfile = "rules.tamper." + tampname
# #
# #             tamp_obj = __import__(tampfile, fromlist=tampname)
# #
# #             filter_func = getattr(tamp_obj, tampname)
# #             input_control = getattr(tamp_obj, tampname + "_controlled")
# #
# #             return """
# # Tamper Name:
# #     {}
# #
# # Filter Func:
# # {}
# #
# # Input Control:
# # {}
# # """.format(tampname, pprint.pformat(filter_func, indent=4), pprint.pformat(input_control, indent=4))
# #         else:
# #             logger.error("[Info] no tamper name {]".format(key))
# #
# #     return ""
#
#
# def search_project(search_type, keyword, keyword_value, with_vuls=False):
#     """
#     根据信息搜索项目信息
#     :param with_vuls:
#     :param search_type:
#     :param keyword:
#     :param keyword_value:
#     :return:
#     """
#     if search_type == 'vendor':
#         ps = get_project_by_version(keyword, keyword_value)
#         table = PrettyTable(
#             ['#', 'ProjectId', 'Project Name', 'Project Origin', 'Vendor', 'Version'])
#
#         table.align = 'l'
#
#         table2 = PrettyTable(
#             ['#', 'Vuln ID', 'Title', 'level', 'CVE', 'Reference', 'Vendor', 'Affected Version'])
#
#         table2.align = 'l'
#         i = 0
#         j = 0
#
#         if not ps:
#             return False
#
#         for p in ps:
#             pid = p.id
#             pname = p.project_name
#             porigin = p.project_origin
#             vs = ps[p]
#
#             for v in vs:
#                 i += 1
#                 vendor_name = v.name
#                 vendor_vension = v.version
#
#                 table.add_row([i, pid, pname, porigin, vendor_name, vendor_vension])
#
#         logger.info("Project List (Small than {} {}):\n{}".format(keyword, keyword_value, table))
#         logger.info("Vendor {}:{} Vul List:\n{}".format(keyword, keyword_value, table2))
#
#     return True



