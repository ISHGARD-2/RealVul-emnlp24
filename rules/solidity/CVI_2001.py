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


class CVI_2001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 2001
        self.language = "solidity"
        self.author = "LoRexxar"
        self.vulnerability = "假充值 vul"
        self.description = "开发人员没有遵循ERC20"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = ['\\bif\\s*\\(.+(?=\\))\\)\\s*\\{[^\\}]+\\}\\s*else\\s*\\{[\\s]+return\\s+false;']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
