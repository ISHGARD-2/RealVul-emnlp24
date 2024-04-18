# -*- coding: utf-8 -*-
import re

from utils.utils import match_pair


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

    def get_content(self, code, para):
        tmp_code = ""
        if code[:4] == "echo":
            tmp_code = code[5:]
        elif code[:5] == "print":
            tmp_code = code[6:]
        else:
            tmp_code = code[code.find(' '):]

        # Annotate other variables
        matchs = self.main(tmp_code, with_position=True)
        if not matchs:
            return tmp_code

        output_code = tmp_code
        for match, positions in zip(matchs[0], matchs[1]):
            if match == para:
                continue

            lp, rp = positions[0], positions[1]

            if rp< len(tmp_code) and tmp_code[rp] == '[':
                pair = match_pair(tmp_code[rp:], '[', ']')
                if not pair:
                    return tmp_code

                rp += pair[1]+1

            match_code = tmp_code[lp:rp]
            output_code = output_code.replace(match_code, "_PAD_")

        if not output_code.strip().endswith(';'):
            output_code += ';'
        return output_code

    def complete_slice_end(self, vul_slice, code, para):
        tmp_code = self.get_content(code, para['name'])
        if para['name'] not in tmp_code:
            return None

        vul_output = "echo " + str(tmp_code) + "\t\t//sink point: " + para['name']

        tmp = vul_slice.split(code)

        output = ""
        for i, s in enumerate(tmp):
            if i == 0 and len(tmp) > 1:
                output += s
            elif i + 1 == len(tmp):
                output += vul_output + s
            elif i == 0 and len(tmp) == 1:
                output += s + vul_output
            else:
                output += code + s

        return output
