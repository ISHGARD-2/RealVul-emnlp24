import copy
import codecs
from utils.log import logger
from phply import phpast as php
from core.pretreatment import ast_object
from core.pretreatment import ast_gen


class PhpRootNode():
    def __init__(self, nodes):
        self.name = 'root'
        self.nodes = nodes


class FuncCall:
    """
    self.function_list:list        # nodes of function call
        func_name:str
        func_type:phpast object
        father_list:[{"name": 'func_name', "type": func_type}, ...]
        node_ast:ast
        code:str

    self.call_graph:list


    """

    def __init__(self, target_path, special_rules, formatter='csv', output='', black_path=None, a_sid=None):
        self.function_list = []
        self.call_graph = []

        self.target_path = target_path
        self.formatter = formatter
        self.output = output
        self.special_rules = special_rules
        self.black_path = black_path
        self.aid = a_sid
        self.pa = ast_gen(ast_object, target_path, formatter, output, special_rules)

        file = codecs.open(target_path, "r", encoding='utf-8', errors='ignore')
        self.code_content = file.read().split('\n')

    def call_graph_gen(self):
        all_nodes = ast_object.get_nodes(self.target_path)

        # add root zone code as a function
        self.init_function_list(all_nodes, [{"name": 'root', "type": None}])
        self.analysis_functions(all_nodes, [{"name": 'root', "type": None}], isroot=True)

        # root code
        # self.analysis_call(all_nodes, None)
        #
        # # function code
        # for func in self.function_list:
        #     self.analysis_call(func["node_ast"].nodes, func["father_list"])

        return

    def analysis_call(self, nodes, zone):
        """
        get all FunctionCall/MethodCall
        about to complete
        """
        for node in nodes:
            if isinstance(node, php.Class) or isinstance(node, php.Function) or isinstance(node, php.Method):
                continue

            elif isinstance(node, php.FunctionCall):
                isfind = self.func_match(node, php.FunctionCall)

                if isfind:
                    pass
                else:
                    pass

            elif isinstance(node, php.MethodCall):
                isfind = self.func_match(node, php.MethodCall)
        return

    def func_match(self, node, type):
        """
        match functionCall with function in self.function_list
        """
        func_call_name = node.name

        same_name_func = []
        for func in self.function_list:
            if func["node_name"] == func_call_name and type == func["node_type"]:
                same_name_func.append(func)

        # analysis which function can functioncall  access
        # ...

        return same_name_func

    def init_function_list(self, nodes, father_list):
        """
        treat root code content as a function without title
        add to function_list
        """
        new_nodes = []
        new_code = "\n".join(self.code_content[0:nodes[0].lineno-1])

        for i, node in enumerate(nodes):
            if isinstance(node, php.Class) or isinstance(node, php.Function) or isinstance(node, php.Method):
                continue

            start_pos = node.lineno -1
            if i+1 == len(nodes):
                end_pos = -1
            else:
                end_pos = nodes[i + 1].lineno -1
            new_code += "\n" + "\n".join(self.code_content[start_pos:end_pos])

            new_nodes.append(node)

        root_node = {}
        root_node["node_name"] = "root"
        root_node["node_type"] = None
        root_node["father_list"] = []
        root_node["node_ast"] = PhpRootNode(new_nodes)
        root_node["code"] = new_code

        self.function_list.append(root_node)


    def analysis_functions(self, nodes, father_list, isroot=False):
        """
        get all function, Method
        """

        for i, node in enumerate(nodes):
            if hasattr(node, "name"):
                new_node_name = node.name
            else:
                new_node_name = node.__class__.__name__
            new_node_type = node.__class__


            if isinstance(node, php.Class) or isinstance(node, php.Function) or isinstance(node, php.Method):
                if not isinstance(node, php.Class):
                    # prepare code of function/method
                    next_node = None
                    if i+1 < len(nodes):
                        next_node = nodes[i + 1]
                    node_code = self.get_func_code(node, next_node)

                    # prepare function/method information
                    node_info = {}
                    node_info["node_name"] = node.name
                    node_info["node_type"] = node.__class__
                    node_info["father_list"] = father_list
                    node_info["node_ast"] = node
                    node_info["code"] = node_code

                    self.function_list.append(node_info)

                new_father_list = copy.deepcopy(father_list)
                new_father_list.append({"name": new_node_name, "type": new_node_type})

            else:
                new_father_list = father_list

            if hasattr(node, "node"):
                new_nodes = [node.node]
            elif hasattr(node, "nodes"):
                new_nodes = node.nodes
            else:
                continue
                # logger.error("[ERROR] node has node attr node/nodes, node: {}  {}".format(new_node_name, new_node_type))

            self.analysis_functions(new_nodes, new_father_list)

    def get_func_code(self, node, next_node):
        """
        get code content of function
        """
        start_lineno = node.lineno-1
        last_lineno = -1
        if next_node:
            last_lineno = next_node.lineno-1

        func_code = '\n'.join(self.code_content[start_lineno:last_lineno])

        if next_node:
            return func_code

        # last node
        stack_count = 1
        tem_code = func_code[func_code.find('{')+1:]
        last_pos = func_code.find('{')+1
        cal_count = 0
        while stack_count != 0:
            if cal_count > 100000:
                logger.error("[ERROR] get_func_code(): iter error, code: {}".format(tem_code))
                exit()
            left_pos = tem_code.find('{')+1
            righ_pos = tem_code.find('}')+1

            if left_pos < righ_pos:
                stack_count += 1
                tem_code = tem_code[left_pos:]
                last_pos += left_pos
            else:
                stack_count -= 1
                tem_code = tem_code[righ_pos:]
                last_pos += righ_pos

        func_code = func_code[:last_pos]
        return func_code