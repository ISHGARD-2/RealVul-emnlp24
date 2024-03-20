
from phply.phplex import lexer  # 词法分析
from phply.phpparse import make_parser  # 语法分析
from phply import phpast as php
from utils.file import check_comment

from utils.log import logger
from configs.const import ext_dict

import gc
import os
import codecs
import traceback
import queue
import asyncio


class Pretreatment:

    def __init__(self, name="root"):
        self.name = name
        self.file_list = []
        self.target_queue = queue.Queue()
        self.target_directory = ""
        self.lan = None
        self.is_unprecom = False

        self.pre_result = {}
        self.define_dict = {}

        # self.pre_ast_all()

    def init_pre(self, target_directory, files):
        self.file_list = files
        self.target_directory = target_directory

        self.target_directory = os.path.normpath(self.target_directory)
        for fileext in self.file_list:
            self.target_queue.put(fileext)

    def get_path(self, filepath):
        os.chdir(os.path.dirname(os.path.dirname(__file__)))

        if os.path.isfile(filepath):
            return os.path.normpath(filepath)

        if os.path.isfile(os.path.normpath(os.path.join(self.target_directory, filepath))):
            return os.path.normpath(os.path.join(self.target_directory, filepath))

        if os.path.isfile(self.target_directory):
            return os.path.normpath(self.target_directory)
        else:
            return os.path.normpath(os.path.join(self.target_directory, filepath))

    def pre_ast_all(self, lan=None, is_unprecom=False):

        # 设置公共变量用于判断是否设定了扫描语言
        self.lan = lan
        # 设置标志位标识跳过预编译阶段
        self.is_unprecom = is_unprecom

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        scan_list = (self.pre_ast() for i in range(10))
        loop.run_until_complete(asyncio.gather(*scan_list))

    async def pre_ast(self):

        while not self.target_queue.empty():

            fileext = self.target_queue.get()

            if not self.lan:
                break

            if fileext[0] in ext_dict['php'] and 'php' in self.lan:
                # 下面是对于php文件的处理逻辑
                for filepath in fileext[1]['list']:
                    all_nodes = []
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'php'
                    self.pre_result[filepath]['ast_nodes'] = []

                    fi = codecs.open(filepath, "r", encoding='utf-8', errors='ignore')
                    code_content = fi.read()
                    code_content = check_comment(code_content)
                    fi.close()

                    # self.pre_result[filepath]['content'] = code_content

                    try:
                        if not self.is_unprecom:
                            parser = make_parser()
                            all_nodes = parser.parse(code_content, debug=False, lexer=lexer.clone(), tracking=True)
                        else:
                            all_nodes = []

                        # 合并字典
                        self.pre_result[filepath]['ast_nodes'] = all_nodes

                    except SyntaxError as e:
                        logger.warning('[AST] [ERROR] parser {} SyntaxError'.format(filepath))
                        continue

                    except AssertionError as e:
                        logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))
                        continue

                    except:
                        logger.warning('[AST] something error, {}'.format(traceback.format_exc()))
                        continue

                    # 搜索所有的常量
                    for node in all_nodes:
                        if isinstance(node, php.FunctionCall) and node.name == "define":
                            define_params = node.params

                            if define_params:
                                logger.debug(
                                    "[AST][Pretreatment] new define {}={}".format(define_params[0].node,
                                                                                  define_params[1].node))

                                key = define_params[0].node
                                if isinstance(key, php.Constant):
                                    key = key.name

                                self.define_dict[key] = define_params[1].node

            # 手动回收?
            gc.collect()

        return True

    def get_nodes(self, filepath, vul_lineno=None, lan=None):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result:
            return self.pre_result[filepath]['ast_nodes']

        elif os.path.join(self.target_directory, filepath) in self.pre_result:
            return self.pre_result[os.path.join(self.target_directory, filepath)]['ast_nodes']

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return False


ast_list = []
ast_object=Pretreatment()

def gen_ast(name):
    ast = Pretreatment(name)
    ast_list.append({"name": ast})
    return ast


def get_ast_by_name(name):
    if ast_list[name]:
        return ast_list[name]
    return None



