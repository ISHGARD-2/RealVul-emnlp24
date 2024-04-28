import threading

from phply.phplex import lexer  # 词法分析
from phply.phpparse import make_parser  # 语法分析
from phply import phpast as php
from tqdm import tqdm

from utils.file import check_comment

from utils.log import logger
from configs.const import ext_dict

import gc
import os
import codecs
import traceback
import queue
import asyncio

from utils.utils import support_check


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

    def init_pre(self, target_directory, files, file_list):
        self.file_list = files
        self.target_directory = target_directory

        self.target_directory = os.path.normpath(self.target_directory)
        for fileinfo in file_list:
                self.target_queue.put((fileinfo.full_code, fileinfo.file_path))

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
        logger.info('[PRE-AST] [INFO] AST GENERATING... ')

        scan_list = (self.pre_ast() for i in range(10))
        loop.run_until_complete(asyncio.gather(*scan_list))

    async def pre_ast(self):

        while not self.target_queue.empty():

            (full_code, file_path) = self.target_queue.get()

            # 下面是对于php文件的处理逻辑
            filepath = self.get_path(file_path)
            self.pre_result[filepath] = {}
            self.pre_result[filepath]['language'] = 'php'
            self.pre_result[filepath]['ast_nodes'] = []

            # self.pre_result[filepath]['content'] = code_content

            try:
                if not self.is_unprecom:
                    parser = make_parser()
                    all_nodes = parser.parse(full_code, debug=False, lexer=lexer.clone(), tracking=True)
                else:
                    all_nodes = []

                # 合并字典
                self.pre_result[filepath]['ast_nodes'] = all_nodes

            except SyntaxError as e:
                #logger.warning('[AST] [ERROR] parser {}:{} SyntaxError or phply not support'.format(filepath, str(e.lineno)))
                continue

            except AssertionError as e:
                logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))
                continue

            except:
                logger.warning('[AST] something error, {}'.format(traceback.format_exc()))
                continue

            # 搜索所有的常量
            # for node in all_nodes:
            #     if isinstance(node, php.FunctionCall) and node.name == "define":
            #         define_params = node.params
            #
            #         if define_params:
            #             logger.debug(
            #                 "[AST][Pretreatment] new define {}={}".format(define_params[0].node,
            #                                                               define_params[1].node))
            #
            #             key = define_params[0].node
            #             if isinstance(key, php.Constant):
            #                 key = key.name
            #
            #             self.define_dict[key] = define_params[1].node


    def get_nodes(self, filepath):
        filepath = os.path.normpath(filepath)
        fullpath = os.path.join(self.target_directory, filepath)

        if filepath in self.pre_result:
            return self.pre_result[filepath]['ast_nodes']

        elif fullpath in self.pre_result:
            return self.pre_result[fullpath]['ast_nodes']

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return False

    def clear_none_node(self, filepath):
        filepath = os.path.normpath(filepath)
        fullpath = os.path.join(self.target_directory, filepath)
        allnodes = []

        if filepath in self.pre_result:
            allnodes = self.pre_result[filepath]['ast_nodes']

        elif fullpath in self.pre_result:
            allnodes = self.pre_result[fullpath]['ast_nodes']

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return None

        allnodes = self.pop_none_node(allnodes)


        if filepath in self.pre_result:
            self.pre_result[filepath]['ast_nodes'] = allnodes

        elif fullpath in self.pre_result:
            self.pre_result[fullpath]['ast_nodes'] = allnodes

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return None

    def pop_none_node(self, nodes):

        for i, node in enumerate(nodes):
            if node is None:
                del nodes[i]
                continue

            is_recursion = False
            if isinstance(node, php.If) or isinstance(node, php.ElseIf) \
                    or isinstance(node, php.DoWhile) or isinstance(node, php.Foreach) or isinstance(node, php.While) \
                    or isinstance(node, php.Switch) or isinstance(node, php.Case):
                is_recursion = True


            elif isinstance(node, php.Block) or isinstance(node, php.Echo) or isinstance(node, php.Print):
                is_recursion = True

            # Scope zone
            if isinstance(node, php.Class) or isinstance(node, php.Function) or isinstance(node, php.Method):
                is_recursion = True


            # next node
            if is_recursion:
                if hasattr(node, "node"):
                    new_nodes = [node.node]
                    self.pop_none_node(new_nodes)
                if hasattr(node, "nodes"):
                    new_nodes = node.nodes
                    self.pop_none_node(new_nodes)
                if hasattr(node, "elseifs") and node.elseifs:
                    new_nodes = node.elseifs
                    self.pop_none_node(new_nodes)
                if hasattr(node, "else_") and node.else_:
                    new_nodes = [node.else_.node]
                    self.pop_none_node(new_nodes)
                else:
                    continue

        return nodes



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


def get_var_by_ast(node):
    if isinstance(node, php.Variable) or \
            isinstance(node, php.ClassVariable) or \
            isinstance(node, php.StaticVariable):
        return node.name
    return ''


