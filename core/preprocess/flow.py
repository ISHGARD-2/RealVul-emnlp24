from phply import phpast as php
from utils.utils import match_pair
from utils.log import logger

class Flow:
    """
    "name": "if",
    "subnode": [],
    "lineno": node.lineno,
    "flag":0
    """
    def __init__(self, name, subnode, lineno):
        self.name = name
        self.subnode = subnode
        self.lineno = lineno
        self.flag = 0
        self.code = ""
        self.self_code = ""

    def set_flag(self):
        self.flag = 1

    def clear_flag(self):
        self.flag =0
        if self.subnode.__class__.__name__ == 'list':
            for flow in self.subnode:
                flow.clear_flag()

    def set_inner_sp(self, inner_start_position):
        self.inner_start_position = inner_start_position

    def set_inner_ep(self, inner_end_position):
        self.inner_end_position = inner_end_position

    def set_end_lineno(self, end_lineno):
        self.end_lineno = end_lineno

    def set_flow_position(self, all_code_position, self_code_position):
        self.all_code_position = all_code_position
        self.self_code_position = self_code_position
        for codeline in self.all_code_position:
            self.code += codeline['code'] + '\n'
        self.code = self.code[:-1]

        for codeline in self.self_code_position:
            self.self_code += codeline['code'] + '\n'
        self.self_code = self.self_code[:-1]


    def set_base_flow(self, nodes, func):
        all_code_position = func.code_line
        self_code_position = []
        if func.func_name == 'root' and func.func_type == None:
            for i, code_line in enumerate(func.code_line):
                if i+1 < nodes[0].lineno:
                    self_code_position.append(code_line)
        else:
            self_code_position = self.get_self_code_position(func, func.code_line)

        self.set_flow_position(all_code_position, self_code_position)



    def set_if_flow(self, node, func, start_pos, end_pos):
        if_flow = Flow("if", [], node.lineno)
        all_code_position = if_flow.get_all_code_position(func, start_pos, end_pos)
        self_code_position = if_flow.get_self_code_position(func, all_code_position)
        if_flow.set_flow_position(all_code_position, self_code_position)

        if_flow = control_flow_analysis(node.node.nodes, if_flow, func, if_flow.inner_start_position, if_flow.inner_end_position)


        # for eif in node.elseifs:
            # elseif_flow = Flow("elseif", [], eif.lineno)
            # elseif_flow = control_flow_analysis(eif, elseif_flow, func)
            # if_flow.subnode.append(elseif_flow)

        if node.else_:
            else_flow = Flow("else", [], node.else_.lineno)
            else_start_pos = self_code_position[-1]['position'][1]
            else_end_pos = end_pos
            all_code_position = else_flow.get_all_code_position(func, else_start_pos, else_end_pos)

            if node.else_.node.__class__.__name__ == "If":

                self_code_position = else_flow.get_self_code_position(func, all_code_position, match_word="else")
                else_flow.set_flow_position(all_code_position, self_code_position)

                else_flow = control_flow_analysis([node.else_.node], else_flow, func, else_flow.inner_start_position, else_flow.inner_end_position)
                if_flow.subnode.append(else_flow)
            elif node.else_.node.__class__.__name__ == "Block" and len(node.else_.node.nodes) > 0:

                self_code_position = else_flow.get_self_code_position(func, all_code_position, match1=False)
                else_flow.set_flow_position(all_code_position, self_code_position)

                else_flow = control_flow_analysis(node.else_.node.nodes, else_flow, func, else_flow.inner_start_position, else_flow.inner_end_position)
                if_flow.subnode.append(else_flow)
        self.subnode.append(if_flow)

    def set_while_flow(self, node, func, start_pos, end_pos):
        while_flow = Flow("while", [], node.lineno)

        all_code_position = while_flow.get_all_code_position(func, start_pos, end_pos)
        self_code_position = while_flow.get_self_code_position(func, all_code_position)
        while_flow.set_flow_position(all_code_position, self_code_position)

        while_flow = control_flow_analysis(node.node.nodes, while_flow, func, while_flow.inner_start_position, while_flow.inner_end_position)
        self.subnode.append(while_flow)

    def set_foreach_flow(self, node, func, start_pos, end_pos):
        foreach_flow = Flow("foreach", [], node.lineno)

        all_code_position = foreach_flow.get_all_code_position(func, start_pos, end_pos)
        self_code_position = foreach_flow.get_self_code_position(func, all_code_position)
        foreach_flow.set_flow_position(all_code_position, self_code_position)

        while_flow = control_flow_analysis(node.node.nodes, foreach_flow, func, foreach_flow.inner_start_position,
                                           foreach_flow.inner_end_position)
        self.subnode.append(while_flow)

    def set_others_flow(self, node, func, start_pos, end_pos):
        sub_flow = Flow("others", node, node.lineno)
        self.subnode.append(sub_flow)

        self_code_position = sub_flow.get_all_code_position(func, start_pos, end_pos)
        sub_flow.set_flow_position(self_code_position, self_code_position)


    def get_self_code_position(self, func, all_code_position, match1=True, match_word=""):
        self_code_position = []
        all_code = ""
        for code_line in all_code_position:
            all_code += code_line['code']+'\n'
        all_code = all_code[:-1]

        realm_sp = all_code_position[0]["position"][0]

        #match '... else ...'
        if match_word != "":
            l_pos = all_code.find(match_word) + realm_sp
            r_pos = l_pos + len(match_word)
            self_code_position = self.get_all_code_position(func, l_pos, r_pos)
            self.set_inner_sp(r_pos)
            self.set_inner_ep(all_code_position[-1]['position'][1])
            return self_code_position

        # match '... else {...}'
        r_pos = 0
        if match1:
            lr_pos = match_pair(all_code, '(', ')')
            if not lr_pos:
                logger.error("[ERROR] Flow.set_base_flow(): 1")
            r_pos = lr_pos[1]


        lr_pos = match_pair(all_code[r_pos:], '{', '}')
        if not lr_pos:
            logger.error("[ERROR] Flow.set_base_flow(): 2")
        l_pos, r_pos = lr_pos[0] + r_pos, lr_pos[1] + r_pos
        l_pos, r_pos = l_pos + realm_sp, r_pos + realm_sp
        self.set_inner_sp(l_pos+1)
        self.set_inner_ep(r_pos)

        for i, code_line in enumerate(all_code_position):
            if code_line["position"][0] < l_pos:
                if code_line["position"][1] < l_pos:
                    self_code_position.append(code_line)
                else:
                    tp = l_pos - code_line["position"][0]
                    range = 0
                    if tp + 1 == len(code_line['code']):
                        range = 1

                    new_code_line = {'lineno': code_line['lineno'],
                                     'position': (code_line["position"][0], l_pos + 1+range),
                                     'code': code_line['code'][:tp + 1]}
                    self_code_position.append(new_code_line)
            elif code_line["position"][1] > r_pos:
                if code_line["position"][0] > r_pos:
                    break
                else:
                    tp = r_pos - code_line["position"][0]
                    range = 0
                    if tp+1 == len(code_line['code']):
                        range = 1

                    new_code_line = {'lineno': code_line['lineno'],
                                     'position': (r_pos, r_pos+1+range),
                                     'code': code_line['code'][tp:tp+1]}
                    self_code_position.append(new_code_line)
        return self_code_position


    def get_all_code_position(self, func, start_pos, end_pos):
        all_code_position = []

        for i, code_line in enumerate(func.code_line):
            position0 = code_line["position"][0]
            position1 = code_line["position"][1]
            # \n po... sp ...p1 \n  ...ep ...
            if position1 > start_pos >= position0 and position1 <= end_pos:
                new_code_line = {'lineno': code_line['lineno'],
                                 'position': (start_pos, position1),
                                 'code': code_line['code'][start_pos - position0:]}
                all_code_position.append(new_code_line)

            # ... sp ...\n p0 ... p1 \n ...ep ...
            elif start_pos <= position0 and position1 <= end_pos:
                all_code_position.append(code_line)

            # ... sp ...\n p0 ...ep...  p1 \n  ...
            elif start_pos <= position0 and position1 >= end_pos > position0:
                new_code_line = {'lineno': code_line['lineno'],
                                 'position': (position0, end_pos),
                                 'code': code_line['code'][:end_pos - position0]}
                all_code_position.append(new_code_line)

            # \n p0 ... sp ...ep...  p1 \n  ...
            elif position0 <= start_pos and end_pos <= position1:
                new_code_line = {'lineno': code_line['lineno'],
                                 'position': (start_pos, end_pos),
                                 'code': code_line['code'][start_pos - position0:end_pos - position0]}
                all_code_position.append(new_code_line)

        return all_code_position


def control_flow_analysis(nodes, base_flow, func, start_pos0=None, end_pos0=None):

    for i, node in enumerate(nodes):
        code_line = func.get_code_by_lineno(node.lineno)
        start_pos = code_line['position'][0]

        if i+1 == len(nodes):
            if end_pos0:
                end_pos = end_pos0
            else:
                if base_flow.name == 'base':
                    end_pos = base_flow.all_code_position[-1]['position'][-1]
                else:
                    end_pos = base_flow.self_code_position[-1]['position'][-1]
        else:
            next_node_lineno = nodes[i+1].lineno
            next_code_line = func.get_code_by_lineno(next_node_lineno)
            if not code_line:
                logger.error("[ERROR] flow.control_flow_analysis(): 1")
            end_pos = next_code_line['position'][0]

        if start_pos0 and start_pos0>start_pos:
            start_pos = start_pos0
        if end_pos0 and end_pos0<end_pos:
            end_pos = end_pos0

        if isinstance(node, php.If):
            base_flow.set_if_flow(node, func, start_pos, end_pos)

        # elif isinstance(node, php.DoWhile):

        elif isinstance(node, php.Foreach):
            base_flow.set_foreach_flow(node, func, start_pos, end_pos)

        elif isinstance(node, php.While):
            base_flow.set_while_flow(node, func, start_pos, end_pos)

        # elif isinstance(node, php.Switch):
        #
        # elif isinstance(node, php.Case):

        else:
            base_flow.set_others_flow(node, func, start_pos, end_pos)

    return base_flow