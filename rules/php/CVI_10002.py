import re

from utils.my_utils import match_params, match_pair, match_str


class CVI_10002():
    """
    rule class
    """

    def __init__(self):

        self.svid = 10002
        self.cwe = '89'
        self.language = "php"
        self.vulnerability = "SQLI"
        self.description = "SQL injection"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = r"([\"']+\s*(select|SELECT|insert|INSERT|update|UPDATE|DELETE|delete)\s+([^;]*)\$([^;]+?)['\"]*(.+?)?(((?=\))(?!.+\)))|([^\)](?=;)(?!.+;))))"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = None

    def get_content(self, code, para):
        tmp_code = code

        # Annotate other variables
        matchs = match_params(tmp_code, with_position=True)
        if not matchs:
            return tmp_code

        output_code = tmp_code
        for match, positions in zip(matchs[0], matchs[1]):
            if match == para:
                continue

            lp, rp = positions[0], positions[1]

            if rp < len(tmp_code) and tmp_code[rp] == '[':
                pair = match_pair(tmp_code[rp:], '[', ']')
                if not pair:
                    return tmp_code

                rp += pair[1] + 1

            match_code = tmp_code[lp:rp]
            output_code = output_code.replace(match_code, "_PAD_")

        if output_code.strip().endswith(';'):
            output_code = output_code.strip()[:-1]

        index = 0
        while index < len(output_code):
            while index < len(output_code) and output_code[index] not in ['\"', '\'', '(', ')', ',', '[', ']']:
                index += 1

            if index >= len(output_code) or output_code[index] == ')' or output_code[index] == ',' or output_code[index] == ']':
                output_code = output_code[:index]
                break

            match_char1 = output_code[index]
            if match_char1 == '(':
                match_char2 = ')'
            elif match_char1 == '[':
                match_char2 = ']'
            else:
                match_char2 = match_char1

            pair = match_pair(output_code[index:], match_char1, match_char2, instr=True)
            if pair is None:
                output_code += match_char2
                break
            else:
                endpos = pair[1]
                index += endpos + 1

                lstr = output_code[:index]
                rstr = output_code[index + 1:]

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

        vul_output = "$query = " + str(tmp_code) + "\t\t//sink point: " + para['name'] + ';'
        vul_output += "\n$res = mysql_query($query);"

        vul_slice = vul_slice.replace('$query', '$query0')
        tmp_lines = vul_slice.split('\n')

        output = ""
        inserted = False
        for i, s in enumerate(tmp_lines):
            if code in s:
                output += vul_output + '\n'
                inserted = True
            else:
                output += s + '\n'
        if not inserted:
            return None
        return output