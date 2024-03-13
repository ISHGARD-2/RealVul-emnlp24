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


