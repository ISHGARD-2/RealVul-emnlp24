import re
import os
import time
import traceback
from utils.log import logger
from configs.const import ext_dict
from utils.utils import match_pair, match_str

ext_list = []
for e in ext_dict:
    ext_list += ext_dict[e]


def file_list_parse(filelist, language=None):
    result = []
    self_ext_list = ext_list

    if not filelist:
        return result

    if language is not None and language in ext_dict:
        self_ext_list = ext_dict[language]

    for file in filelist:
        # * for base
        if file[0] in self_ext_list or '*' in self_ext_list:
            result.extend(file[1]['list'])

    return result


def check_filepath(target, filepath):
    os.chdir(os.path.dirname(os.path.dirname(__file__)))

    if os.path.isfile(os.path.join(target, filepath)):
        return os.path.join(target, filepath)
    elif os.path.isfile(filepath):
        return filepath
    elif os.path.isfile(target):
        return target
    else:
        return False


def check_phply_syntax(code):
    """
    find whether stmt end with ';' in one php block
    """
    for i in range(len(code) - 1, -1, -1):
        chr = code[i]
        if chr in [';', '{', '}', ':']:
            return code
        elif chr in ['\f', '\n', '\r', '\t', '\v', '\n', ' ']:
            continue
        else:
            return code + ';'


def check_html(content, remove_php=True):
    clear_str = "<?php"
    start_pos = match_str(content, "<?php", out_php=True)
    if start_pos  < 0:
        return content

    while start_pos >= 0:
        if remove_php:
            # len of '<?php' and '?>'
            start_len = 5
            end_len = 0
        else:
            start_len = 0
            end_len = 2

        html_code = content[:start_pos]
        content = content[start_pos + start_len:]

        for char in html_code:
            if char in ['\f', '\n', '\r', '\t', '\v', '\n', ' ']:
                clear_str += char
        # if html_code.count('\n') == 0:
        #     clear_str += '\n'

        end_pos = match_str(content, "?>")

        if end_pos > 0:
            new_clear_str = check_phply_syntax(content[:end_pos + end_len])
            if not new_clear_str:
                # logger.error("[DEBUG] check_html(): 1 ,code:\n{}".format(content))
                clear_str += content[:end_pos + end_len]
            else:
                clear_str += new_clear_str
            content = content[end_pos + 2:]
        else:
            clear_str += content
            break

        start_pos = match_str(content, "<?php", out_php=True)

    return clear_str

def check_end_line_brackets(content, chr):
    # { }
    back_str = ""
    check = False
    string_count = 0

    for i, c in enumerate(content):
        if string_count > 0:
            string_count -= 1
            back_str += c
            continue

        if not check and c in chr:
            check = True
            back_str += c
            continue

        if check :
            if c == '\n':
                back_str += c
                check = False
                continue
            elif c in ['\f', '\n', '\r', '\t', '\v', '\n', ' ']:
                back_str += c
                continue
            else:
                back_str += '\n'+c
                if c in chr:
                    continue
                else:
                    check = False
                    continue

        if  c == '\'' and string_count == 0:
            pair_pos = match_pair(content[i:], '\'', '\'', instr=True)
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0]

        if  c == '\"' and string_count == 0:
            pair_pos = match_pair(content[i:], '\"', '\"', instr=True)
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0]

        back_str += c

    return back_str


def check_end_line(content):
    start_pos = match_str(content, ';', without_brackets=True)
    end_pos = match_str(content[start_pos + 1:], ';', without_brackets=True) + start_pos + 1

    if end_pos < 0 or start_pos < 0:
        return content

    backstr = content[:start_pos + 1]

    while end_pos >= 0:
        append = False
        if '\n' not in content[start_pos + 1:end_pos]:
            append = True

        if append:
            backstr += '\n' + content[start_pos + 1:end_pos + 1]
        else:
            backstr += content[start_pos + 1:end_pos + 1]

        start_pos = end_pos
        end_pos = match_str(content[start_pos + 1:], ';', without_brackets=True)
        if end_pos >= 0:
            end_pos += start_pos + 1

    backstr += content[start_pos + 1:]

    return backstr


def check_end_line_elseif(content):
    backstr = ""
    start_pos = match_str(content, 'elseif')
    while start_pos>=0:
        backstr += content[:start_pos] + "else if"
        content = content[start_pos+6:]

        start_pos = match_str(content, 'elseif')
    backstr += content
    return backstr


def clear_slice(slice):
    for char in ['{', '}']:
        slice = slice.replace(char, char + '\n')

    slice_split = slice.split('\n')
    new_slice = ""

    # clear multy '\n'
    for line in slice_split:
        reserve = False
        for char in line:
            if char not in [' ', '\t', '\r', '\f', '\v']:
                reserve = True
        if reserve:
            new_slice += line + '\n'
    return new_slice


def check_comment(content, check_inner_content=True):
    backstr = ""
    lastchar = ""
    isinlinecomment = False
    isduolinecomment = False
    string_count = 0

    for i, char in enumerate(content):
        # pass string
        if not isinlinecomment and not isduolinecomment and char == '\'' and string_count == 0:
            pair_pos = match_pair(content[i:], '\'', '\'', instr=True)
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0] + 1

        if not isinlinecomment and not isduolinecomment and char == '\"' and string_count == 0:
            pair_pos = match_pair(content[i:], '\"', '\"', instr=True)
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0] + 1
        if string_count > 200:
            pass
        if string_count > 0:
            string_count -= 1
            lastchar = char
            backstr += char
            continue

        if char == '/' and lastchar == '/' and not isduolinecomment:
            backstr = backstr[:-1]
            isinlinecomment = True
            lastchar = ""
            continue
        if char == '#' and not isduolinecomment:
            isinlinecomment = True
            continue

        if isinlinecomment and not isduolinecomment:
            if char == '\n':
                isinlinecomment = False

                lastchar = ''
                backstr += '\n'
            elif char == '>' and i > 1 and content[i - 1] == '?':
                isinlinecomment = False
                lastchar = ''
                backstr += '?>'
            continue

        if char == '\n':
            backstr += '\n'
            continue

        # 多行注释
        if char == '*' and lastchar == '/':
            isduolinecomment = True
            backstr = backstr[:-1]
            lastchar = ""
            continue

        if isduolinecomment:

            if char == '/' and lastchar == '*':
                isduolinecomment = False
                lastchar = ""
                continue

            lastchar = char
            continue

        lastchar = char
        backstr += char

    backstr = check_html(backstr)
    if check_inner_content:
        backstr = check_end_line(backstr)
        backstr = check_end_line_brackets(backstr, ['{', '}'])
        backstr = check_end_line_elseif(backstr)

    return backstr


class FileParseAll:
    def __init__(self, filelist, target, language='php'):
        self.filelist = filelist
        self.t_filelist = file_list_parse(filelist, language)
        self.target = target
        self.language = language

    def grep(self, reg, file_list):
        """
        遍历目标filelist，匹配文件内容
        :param reg: 内容匹配正则
        :return: 
        """
        result = []

        for ffile in file_list:
            file = ffile.full_code.split('\n')
            filepath = ffile.target_directory +ffile.file_path
            line_number = 1
            i = 0
            content = ""

            # 逐行匹配问题比较大，先测试为每5行匹配一次
            for l in file:
                line = l+'\n'
                i += 1
                line_number += 1
                content += line

                if i < 10:
                    continue

                i = 0
                # print line, line_number
                if re.search(reg, content, re.I):

                    # 尝试通过以目标作为标志分割，来判断行数
                    # 目标以前的回车数计算
                    p = re.compile(reg)
                    matchs = p.finditer(content)

                    for m in matchs:
                        data = m.group(0).strip()

                        split_data = content.split(data)[0]
                        # enddata = content.split(data)[1]

                        LRnumber = " ".join(split_data).count('\n')

                        match_numer = line_number - 10 + LRnumber

                        result.append((filepath, str(match_numer), data))

                content = ""

            content = check_comment(content)

            # 如果退出循环的时候没有清零，则还要检查一次
            if i > 0:
                if re.search(reg, content, re.I):
                    # 尝试通过以目标作为标志分割，来判断行数
                    # 目标以前的回车数计算
                    p = re.compile(reg)
                    matchs = p.finditer(content)

                    for m in matchs:
                        data = m.group(0).strip()

                        split_data = content.split(data)[0]

                        LRnumber = " ".join(split_data).count('\n')

                        match_numer = line_number - i + LRnumber

                        result.append((filepath, str(match_numer), data))

        return result


class Directory(object):
    """
        :return {'.php': {'count': 2, 'list': ['/path/a.php', '/path/b.php']}}, file_sum, time_consume
    """

    def __init__(self, absolute_path, lans=None):
        self.file_sum = 0
        self.type_nums = {}
        self.result = {}
        self.file = []

        self.absolute_path = absolute_path

        self.ext_list = [ext_dict['php']]

    def collect_files(self):
        t1 = time.time()
        self.files(self.absolute_path)
        self.result['no_extension'] = {'count': 0, 'list': []}
        for extension, values in self.type_nums.items():
            extension = extension.strip()
            if extension:
                self.result[extension] = {'count': len(values), 'list': []}
            # .php : 123
            logger.debug('[PICKUP] [EXTENSION-COUNT] {0} : {1}'.format(extension, len(values)))
            for f in self.file:
                filename = f.split("/")[-1].split("\\")[-1]
                es = filename.split(os.extsep)
                if len(es) >= 2:
                    # Exists Extension
                    # os.extsep + es[len(es) - 1]
                    if f.endswith(extension) and extension:
                        self.result[extension]['list'].append(f)
                else:
                    # Didn't have extension
                    if not extension:
                        self.result['no_extension']['count'] = int(self.result['no_extension']['count']) + 1
                        self.result['no_extension']['list'].append(f)
        if self.result['no_extension']['count'] == 0:
            del self.result['no_extension']
        t2 = time.time()
        # reverse list count
        self.result = sorted(self.result.items(), key=lambda t: t[0], reverse=False)
        return self.result, self.file_sum, t2 - t1

    def files(self, absolute_path, level=1):
        if level == 1:
            logger.debug('[PICKUP] ' + absolute_path)
        try:
            if os.path.isfile(absolute_path):
                filename, directory = os.path.split(absolute_path)
                self.file_info(directory, filename)
            else:
                for filename in os.listdir(absolute_path):
                    directory = os.path.join(absolute_path, filename)

                    # Directory Structure
                    if os.path.isdir(directory):
                        self.files(directory, level + 1)
                    if os.path.isfile(directory):
                        self.file_info(directory, filename)
        except OSError as e:
            logger.error("[PICKUP] {}".format(traceback.format_exc()))
            logger.error('[PICKUP] {msg}'.format(msg=e))
            exit()

    def file_info(self, path, filename):
        # Statistic File Type Count
        file_name, file_extension = os.path.splitext(path)

        # 当设定了lan时加入检查
        # if file_extension.lower() in self.ext_list:

        self.type_nums.setdefault(file_extension.lower(), []).append(filename)

        path = path.replace(self.absolute_path, '')
        self.file.append(path)
        self.file_sum += 1
