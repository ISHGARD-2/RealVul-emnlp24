# -*- coding: utf-8 -*-
import re

class CVI_10001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 10001
        self.language = "php"
        self.vulnerability = "Reflected XSS"
        self.description = "echo参数可控会导致XSS漏洞"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = r"((echo|print)\s+[^;]+(?=(\?>)|;))"


    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        sql_sen = regex_string[0][0]
        reg = "\$\w+"
        if re.search(reg, regex_string, re.I):
            p = re.compile(reg)
            match = p.findall(regex_string)
            return match
        return None

    def get_content(self, code):
        if code[:4] == "echo":
            return code[5:]
        elif code[:5] == "print":
            return code[6:]

    def complete_slice_end(self, code):
        code = self.get_content(code)
        return "$vulchecker_output = " + str(code)
