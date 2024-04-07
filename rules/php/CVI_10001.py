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


    def main(self, regex_string, with_position=False):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        reg = "\\$\\w+"
        if re.search(reg, regex_string, re.I):
            p = re.compile(reg)
            match = p.findall(regex_string)
            matchs = re.finditer(reg, regex_string)

            match_out = []
            positions = []

            for i, mp in enumerate(matchs):
                m = match[i]
                lp = mp.start()
                rp = mp.end()

                if lp > 0 and regex_string[lp - 1] == '\\':
                    continue

                match_out.append(m)
                positions.append((lp, rp))


            if with_position:
                return [match_out, positions]
            return match_out
        return None

    def get_content(self, code):
        if code[:4] == "echo":
            return code[5:]
        elif code[:5] == "print":
            return code[6:]

    def complete_slice_end(self, code):
        code = self.get_content(code)
        return "echo " + str(code)+"\t\t//sink point here."
