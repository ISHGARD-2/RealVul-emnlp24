# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_1010():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1010
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "LDAPI"
        self.description = "LDAP注入可能导致ldap的账号信息泄露"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(ldap_add|ldap_delete|ldap_list|ldap_read|ldap_search|ldap_bind)"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
