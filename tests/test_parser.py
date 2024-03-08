#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    core
    ~~~~~

    Implements core main

    :author:    BlBana <635373043@qq.com>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

from Kunlun_M.settings import PROJECT_DIRECTORY
from core.core_engine.php.parser import anlysis_params
from core.core_engine.php.parser import scan_parser
from core.pretreatment import ast_object

files = [('.php', {'list': ["v_parser.php", "v.php"]})]
ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
ast_object.pre_ast_all(['php'])


target_projects = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_parser.php'
target_projects2 = PROJECT_DIRECTORY + '/tests/vulnerabilities/v.php'

with open(target_projects, 'r') as fi:
    code_contents = fi.read()
with open(target_projects, 'r') as fi2:
    code_contents2 = fi2.read()

sensitive_func = ['system']
lineno = 7

param = '$callback'
lineno2 = 10


def test_scan_parser():
    assert scan_parser(sensitive_func, lineno, target_projects)


def test_anlysis_params():
    assert anlysis_params(param, target_projects2, lineno2)
