from utils.log import logger
from phply import phpast as php
from core.pretreatment import ast_object
from core.pretreatment import ast_gen

class FuncCall:
    """
    self.call_nodes:dict, nodes of function call
        node_name:str
        child_nodes:list


    """
    def __init__(self, target_path, special_rules, formatter='csv', output='', black_path=None, a_sid=None):
        self.call_graph = {}
        self.target_path = target_path
        
        self.formatter = formatter
        self.output = output
        self.special_rules = special_rules
        self.black_path = black_path
        self.aid = a_sid
        ast_gen(target_path, formatter, output, special_rules)


    def call_graph_gen(self):

        return




