
import re
import os
import time
import json
import codecs
import zipfile
import traceback
import jsbeautifier
from utils.log import logger
from configs.const import ext_dict


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

def check_comment(content):
    backstr = ""
    lastchar = ""
    isinlinecomment = False
    isduolinecomment = False

    for char in content:
        if char == '/' and lastchar == '/':
            backstr = backstr[:-1]
            isinlinecomment = True
            lastchar = ""
            continue

        if isinlinecomment:
            if char == '\n':
                isinlinecomment = False

                lastchar = ''
                backstr += '\n'
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

    return backstr


class FileParseAll:
    def __init__(self, filelist, target, language='php'):
        self.filelist = filelist
        self.t_filelist = file_list_parse(filelist, language)
        self.target = target
        self.language = language



    def grep(self, reg):
        """
        遍历目标filelist，匹配文件内容
        :param reg: 内容匹配正则
        :return: 
        """
        result = []

        for ffile in self.t_filelist:
            filepath = check_filepath(self.target, ffile)

            if not filepath:
                continue

            file = codecs.open(filepath, "r", encoding='utf-8', errors='ignore')
            line_number = 1
            i = 0
            content = ""

            # 逐行匹配问题比较大，先测试为每5行匹配一次
            for line in file:
                i += 1
                line_number += 1
                content += line

                if i < 10:
                    continue

                content = check_comment(content)

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
                    logger.debug('[PICKUP] [FILES] ' + '|  ' * (level - 1) + '|--' + filename)
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
