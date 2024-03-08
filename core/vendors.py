#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: vendors.py
@time: 2021/7/21 14:57
@desc:

'''

import os
import re
import json
import codecs
import asyncio
import traceback

import xml.etree.cElementTree as eT
import Kunlun_M.settings as settings

from core.vuln_apis import get_vulns_from_source

from utils.log import logger
from utils.file import check_filepath
from utils.utils import compare_vendor, abstract_version

from Kunlun_M.const import VENDOR_FILE_DICT, VENDOR_CVIID, vendor_source_match

from web.index.models import ProjectVendors, update_and_new_project_vendor, update_and_new_vendor_vuln
from web.index.models import Project, VendorVulns, check_update_or_new_scanresult, get_resultflow_class


def get_project_vendor_by_name(vendor_name):
    """
    支持*语法的查询
    :param vendor_name:
    :return:
    """
    if vendor_name.startswith('*'):
        if vendor_name.endswith('*'):
            pvs = ProjectVendors.objects.filter(name__icontains=vendor_name.strip('*'))

        else:
            pvs = ProjectVendors.objects.filter(name__iendswith=vendor_name.strip('*'))

    else:
        if vendor_name.endswith('*'):
            pvs = ProjectVendors.objects.filter(name__istartswith=vendor_name.strip('*'))

        else:
            pvs = ProjectVendors.objects.filter(name__iexact=vendor_name.strip('*'))

    return pvs


def get_vendor_vul_by_name(vendor_name):
    """
    支持*语法的查询
    :param vendor_name:
    :return:
    """
    if vendor_name.startswith('*'):
        if vendor_name.endswith('*'):
            vvs = VendorVulns.objects.filter(vendor_name__icontains=vendor_name.strip('*'))

        else:
            vvs = VendorVulns.objects.filter(vendor_name__iendswith=vendor_name.strip('*'))

    else:
        if vendor_name.endswith('*'):
            vvs = VendorVulns.objects.filter(vendor_name__istartswith=vendor_name.strip('*'))

        else:
            vvs = VendorVulns.objects.filter(vendor_name__iexact=vendor_name.strip('*'))

    return vvs


def get_project_by_version(vendor_name, vendor_version):
    """
    获取低于该版本的所有项目信息
    :param vendor_name:
    :param vendor_version:
    :return:
    """
    is_need_version_check = True
    result_project = {}

    if vendor_version == 'unknown':
        is_need_version_check = False

    vendor_version = abstract_version(vendor_version)

    if not vendor_version and is_need_version_check:
        return result_project

    pvs = get_project_vendor_by_name(vendor_name.strip())

    for pv in pvs:
        # pv_versions = pv.version.split(',')

        if is_need_version_check and compare_vendor(pv.version, vendor_version):
            pid = pv.project_id
            project = Project.objects.filter(id=pid).first()

            if project not in result_project:
                result_project[project] = [pv]
            else:
                result_project[project].append(pv)

    return result_project


# not support gradle
def get_vulns(language, vendor_name, vendor_version):
    return get_vulns_from_source(language, vendor_name, vendor_version)


def check_and_save_result(task_id, language, vendor_name, vendor_version):
    """
    检查并保存结果。
    :param vendor_name:
    :param vendor_version:
    :return:
    """
    vvs = get_vendor_vul_by_name(vendor_name.strip())
    # vendor_version = abstract_version(vendor_version)
    result_list = []

    for vv in vvs:
        vv_affect_version = vv.affected_versions.split(',')

        if not vendor_version or vendor_version in vv_affect_version:

            if task_id:
                sr = check_update_or_new_scanresult(
                    scan_task_id=task_id,
                    cvi_id=VENDOR_CVIID,
                    language=language,
                    vulfile_path="VendorVul:{}".format(vv.id),
                    source_code="{}".format(vv.reference[:180]),
                    result_type=vendor_source_match,
                    is_unconfirm=False,
                    is_active=True
                )
                #  save into get_resultflow_class
                ResultFlow = get_resultflow_class(int(task_id))

                if sr:
                    node_source = vv.description
                    rf = ResultFlow(vul_id=sr.id, node_type='sca_scan',
                                    node_content=vv.title, node_path=vv.reference[:280],
                                    node_source=node_source, node_lineno=0)
                    rf.save()

            else:
                result_list.append(vv)

    return result_list


def get_and_save_vendor_vuls(task_id, vendor_name, vendor_version, language, ext=None):

    # not support gradle
    if ext == 'gradle':
        return []

    if not settings.WITH_VENDOR and task_id:
        return False

    logger.info("[Vendor Vuls] Spider {} Vendor {} Version {} Vul.".format(language, vendor_name, vendor_version))

    _vendor = {"name": vendor_name, "version": vendor_version}
    for vuln in get_vulns(language, _vendor["name"], _vendor["version"]):
        update_and_new_vendor_vuln(_vendor, vuln)

    return check_and_save_result(task_id, language, _vendor["name"], _vendor["version"])


class Vendors:
    """
    项目组件检查
    """

    def __init__(self, task_id, project_id, target, files):
        self.task_id = task_id
        self.project_id = project_id
        self.target_path = target
        self.files = files

        self.vendor_file_list = []
        self.ext_list = []
        self.exist_file_list = []

        # java temp vendor list
        self.java_temp_vendor_list = {}

        for lan in VENDOR_FILE_DICT:
            self.vendor_file_list.extend(VENDOR_FILE_DICT[lan])

        for vendor_file in self.vendor_file_list:
            es = vendor_file.split(os.extsep)

            if len(es) >= 2:
                self.ext_list.append(".{}".format(es[-1]))

        self.ext_list = list(set(self.ext_list))

        # 检查列表
        self.get_vendor_file()
        self.exist_file_list = list(set(self.exist_file_list))
        self.exist_file_list = sorted(self.exist_file_list, key=lambda i:len(i))

        if len(self.exist_file_list):
            self.check_vendor()

    def get_vendor_file(self):

        for file_obj in self.files:
            for ext in self.ext_list:
                if ext == file_obj[0]:
                    filelist = file_obj[1]['list']

                    for file in filelist:
                        filename = file.split('/')[-1].split('\\')[-1]

                        if filename in self.vendor_file_list:
                            logger.info("[Vendor] Vendor file {} be found in {}.".format(filename, file))

                            self.exist_file_list.append(file)
                            continue

        return self.exist_file_list

    def get_language(self, filename):

        for lan in VENDOR_FILE_DICT:
            if filename in VENDOR_FILE_DICT[lan]:
                return lan

        else:
            return ""

    def check_commit(self, line):
        last_str = ""
        result = ""

        for str in line:
            if last_str == '/' and str == '/':
                result = result[:-1]
                return result

            if str == '#':
                return result

            result += str
            last_str = str

        return result

    def check_vendor(self):
        for file in self.exist_file_list:

            try:
                filepath = check_filepath(self.target_path, file)
                filename = file.split('/')[-1].split('\\')[-1]
                language = self.get_language(filename)

                f = codecs.open(filepath, 'rb+', encoding='utf-8', errors='ignore')
                filecontent = f.read()
                f.seek(0, os.SEEK_SET)
                savefilepath = filepath.replace(self.target_path, "").replace('\\', '/')

                logger.info("[Vendor] Parse File {}.".format(savefilepath))

                if filename == "requirements.txt":

                    for line in f:
                        if not len(line):
                            continue

                        vendor = line.split("==")
                        vendor_name = vendor[0].strip()
                        vendor_version = vendor[-1].strip()
                        if len(vendor) < 2:
                            vendor_version = None
                        ext = "php"

                        update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                      language=language, source=savefilepath, ext=ext)

                        get_and_save_vendor_vuls(self.task_id, vendor_name, vendor_version, language)

                elif filename == 'composer.json':
                    vendors = json.loads(filecontent)
                    vendors_list = []
                    ext = "php"

                    if not len(vendors):
                        continue

                    if 'require' in vendors:
                        vendors_list = vendors['require']

                    for vendor in vendors_list:
                        vendor_name = vendor.strip()
                        vendor_version = vendors_list[vendor].strip()

                        update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                      language=language, source=savefilepath, ext=ext)

                        get_and_save_vendor_vuls(self.task_id, vendor_name, vendor_version, language)

                elif filename == 'go.mod':

                    go_version = ""
                    is_require_line = False

                    for line in f:

                        if line.startswith('go'):
                            go_version = line.strip().split(' ')[-1]

                        if line.startswith('require ('):
                            is_require_line = True
                            continue

                        if line.startswith(')'):
                            is_require_line = False
                            continue

                        if is_require_line:
                            vendor = self.check_commit(line).strip().split(' ')

                            vendor_name = vendor[0].strip()
                            vendor_version = vendor[-1].strip()
                            ext = go_version

                            update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                          language=language, source=savefilepath, ext=ext)

                            get_and_save_vendor_vuls(self.task_id, vendor_name, vendor_version, language)

                elif filename == 'pom.xml':
                    reg = r'xmlns="([\w\.\\/:]+)"'
                    pom_ns = None
                    ext = ""

                    if re.search(reg, filecontent, re.I):

                        p = re.compile(reg)
                        matchs = p.finditer(filecontent)

                        for match in matchs:
                            pom_ns = match.group(1)

                    tree = self.parse_xml(filepath)
                    root = tree.getroot()

                    # 匹配default
                    if pom_ns:
                        default_xpath_reg = ".//{%s}parent" % pom_ns
                    else:
                        default_xpath_reg = ".//parent"

                    parents = root.findall(default_xpath_reg)
                    default_version = "unknown"
                    project_version = "unknown"
                    for parent in parents:
                        project_groupid = list(parent)[0].text
                        project_artifactId = list(parent)[1].text
                        project_version = list(parent)[2].text

                        # project version 格式检查
                        var_reg = "\${([\w\.\_-]+)}"
                        if re.search(var_reg, project_version, re.I):
                            p2 = re.compile(var_reg)
                            matchs = p2.finditer(project_version)

                            for match in matchs:
                                varname = match.group(1)

                                if varname in self.java_temp_vendor_list:
                                    project_version = self.java_temp_vendor_list[varname]
                                    continue

                        # project 依赖版本也可以加入全局表
                        vendor_name = "{}.{}".format(project_groupid, project_artifactId)
                        self.java_temp_vendor_list[vendor_name] = project_version
                        update_and_new_project_vendor(self.project_id, name=vendor_name, version=project_version,
                                                      language=language, source=savefilepath, ext=ext)

                    # 匹配通用配置
                    if pom_ns:
                        java_base_xpath_reg = ".//{%s}properties" % pom_ns
                    else:
                        java_base_xpath_reg = ".//properties"

                    base_tags = root.findall(java_base_xpath_reg)

                    if base_tags:
                        btags = list(base_tags[0])
                        for btag in btags:
                            self.java_temp_vendor_list[btag.tag.replace("{%s}" % pom_ns, "")] = btag.text

                            # 全局表
                            vendor_name = btag.tag.replace("{%s}" % pom_ns, "")
                            self.java_temp_vendor_list[vendor_name] = btag.text
                            update_and_new_project_vendor(self.project_id, name=vendor_name, version=btag.text,
                                                          language=language, source=savefilepath, ext=ext)

                    # 匹配dependency
                    if pom_ns:
                        xpath_reg = ".//{%s}dependency" % pom_ns
                    else:
                        xpath_reg = ".//dependency"

                    childs = root.findall(xpath_reg)
                    for child in childs:
                        group_id = list(child)[0].text
                        artifact_id = list(child)[1].text
                        if len(list(child)) > 2 and "version" in list(child)[2].tag:
                            version = list(child)[2].text
                        else:
                            version = default_version

                        var_reg = "\${([\w\.\_-]+)}"
                        if re.search(var_reg, version, re.I):
                            p2 = re.compile(var_reg)
                            matchs = p2.finditer(version)

                            for match in matchs:
                                varname = match.group(1)

                                # 处理内置变量
                                if varname == "project.version":
                                    version = project_version
                                    continue

                                if varname in self.java_temp_vendor_list:
                                    version = self.java_temp_vendor_list[varname]
                                    continue

                                # if pom_ns:
                                #     var_xpath_reg = ".//{%s}%s" % (pom_ns, varname)
                                # else:
                                #     var_xpath_reg = ".//%s" % varname
                                #
                                # varchilds = root.findall(var_xpath_reg)

                                # for child in varchilds:
                                #     version = child.text
                                #     ext = varname
                                #
                                # # 如果没有匹配到，那么需要去数据库查询
                                # if not varchilds:
                                #     pv = ProjectVendors.objects.filter(project_id=self.project_id, ext=varname).first()
                                #     if pv:
                                #         version = pv.version

                        vendor_name = "{}:{}".format(group_id, artifact_id)
                        vendor_version = version
                        ext = "mevan"

                        logger.debug("[Vendor][pom.xml] Found Vendor {} vension {} in file {}".format(vendor_name, vendor_version, savefilepath))

                        update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                      language=language, source=savefilepath, ext=ext)

                        get_and_save_vendor_vuls(self.task_id, vendor_name, vendor_version, language, ext)

                elif filename == 'build.gradle':
                    is_plugin_block = False
                    ext = "gradle"

                    for line in f:
                        if line.startswith('plugins {'):
                            is_plugin_block = True
                            continue

                        if is_plugin_block and line.startswith('}'):
                            is_plugin_block = False
                            continue

                        if is_plugin_block:
                            plugin_block_list = line.strip().split(' ')
                            last_block = ""
                            vendor_name = ""
                            vendor_version = ""

                            for plugin_block in plugin_block_list:
                                if last_block == 'id':
                                    vendor_name = plugin_block.strip("'").strip('"')

                                if last_block == 'version':
                                    vendor_version = plugin_block.strip("'").strip('"')

                                last_block = plugin_block

                            if vendor_name and vendor_version:
                                update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                              language=language, source=savefilepath, ext=ext)

                                get_and_save_vendor_vuls(self.task_id, vendor_name, vendor_version, language, ext)
                            continue

                elif filename == "package.json":
                    vendors = json.loads(filecontent)

                    if not len(vendors):
                        continue

                    node_version = "{} {}".format(vendors['name'], vendors['version'])
                    dependencies = vendors["dependencies"]
                    devDependencies = vendors["devDependencies"]

                    for dependency in dependencies:
                        vendor_version = dependencies[dependency].strip()
                        ext = "{}.{}".format(node_version, "dependencies")

                        update_and_new_project_vendor(self.project_id, name=dependency, version=vendor_version,
                                                      language=language, source=savefilepath)

                        get_and_save_vendor_vuls(self.task_id, dependency, vendor_version, language, ext)

                    for dependency in devDependencies:
                        vendor_version = devDependencies[dependency].strip()
                        ext = "{}.{}".format(node_version, "devDependencies")

                        update_and_new_project_vendor(self.project_id, name=dependency, version=vendor_version,
                                                      language=language, source=savefilepath)

                        get_and_save_vendor_vuls(self.task_id, dependency, vendor_version, language, ext)

                else:
                    logger.warn("[Vendor] Vendor file {} not support".format(filename))

            except:
                logger.error("[Vendor] Error check for Vendor file {}.\nError: {}".format(file, traceback.format_exc()))
                continue

    @staticmethod
    def parse_xml(file_path):
        return eT.parse(file_path)
