import copy

from utils.log import logger
from phply import phpast as php
from core.pretreatment import ast_object
from core.pretreatment import ast_gen


class FuncCall:
    """
    self.function_list:list        # nodes of function call
        func_name:str
        func_type:phpast object
            None:root
        func_list:list
        father_list:['root', 'xxx_class', ...]
        call_list:[]


    """

    def __init__(self, target_path, special_rules, formatter='csv', output='', black_path=None, a_sid=None):
        self.function_list = []
        self.target_path = target_path

        self.formatter = formatter
        self.output = output
        self.special_rules = special_rules
        self.black_path = black_path
        self.aid = a_sid
        self.pa = ast_gen(target_path, formatter, output, special_rules)

    def call_graph_gen(self):
        all_nodes = ast_object.get_nodes(self.target_path)

        self.analysis_functions(all_nodes, [{"name": 'root', "type": None}], isroot=True)

        return 1

    def get_all_functions(self, nodes):

        return

    def analysis_functions(self, nodes, father_list, isroot=False):
        """
        get all function, Class, Method
        """

        for node in nodes:
            if isinstance(node, php.Class) or isinstance(node, php.Function) or isinstance(node, php.Method):
                node_info = {}
                node_info["node_name"] = node.name
                node_info["node_type"] = node.__class__
                node_info["father_list"] = father_list
                node_info["node_ast"] = node
                self.function_list.append(node_info)

            if hasattr(node, "name"):
                new_node_name = node.name
            else:
                new_node_name = node.__class__.__name__
            new_node_type = node.__class__

            new_father_list =copy.deepcopy(father_list)
            new_father_list.append({"name": new_node_name, "type": new_node_type})

            if hasattr(node, "node"):
                new_nodes = [node.node]
            elif hasattr(node, "nodes"):
                new_nodes = node.nodes
            else:
                continue
                # logger.error("[ERROR] node has node attr node/nodes, node: {}  {}".format(new_node_name, new_node_type))

            self.analysis_functions(new_nodes, new_father_list)

