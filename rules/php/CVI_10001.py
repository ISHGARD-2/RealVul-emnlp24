# -*- coding: utf-8 -*-
import re

from configs.const import REGEX
from utils.my_utils import match_pair, match_params, match_str


class CVI_10001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 10001
        self.language = "php"
        self.cwe = '79'
        self.vulnerability = "XSS"
        self.description = "XSS, echo or print controlable params"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = r"((echo|print)\s+[^;]+(?=(\?>)|;))"

    def get_content(self, code, para):
        tmp_code = ""
        if code[:4] == "echo":
            tmp_code = code[5:]
        elif code[:5] == "print":
            tmp_code = code[6:]
        else:
            tmp_code = code[code.find(' '):]

        # Annotate other variables
        matchs = match_params(tmp_code, with_position=True)
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

        if output_code.strip().endswith(';'):
            output_code = output_code.strip()[:-1]

        index=0
        while index < len(output_code):
            while index < len(output_code) and output_code[index] not in ['\"', '\'']:
                index += 1

            if index >= len(output_code):
                break

            match_char = output_code[index]

            pair = match_pair(output_code[index:], match_char, match_char, instr=True)
            if pair is None:
                output_code += match_char
                break
            else:
                endpos = pair[1]
                index += endpos + 1


                lstr = output_code[:index]
                rstr = output_code[index+1:]

        output_code += ';'
        return output_code

    def complete_slice_end(self, vul_slice, code, para):
        # get sink stmt
        startpos = vul_slice.find(code)
        if not startpos:
            return None

        endpos = match_str(vul_slice[startpos:], ';') + startpos
        code = vul_slice[startpos:endpos]

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




if __name__ == '__main__':
    cvi = CVI_10001()