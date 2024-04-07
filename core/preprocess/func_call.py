import copy
import codecs
import queue
import threading

from tqdm import tqdm

from utils.log import logger
from phply import phpast as php
from core.preprocess.pretreatment import ast_object
from utils.file import FileParseAll, check_comment
from configs.const import BUILTIN_FUNC
from core.preprocess.flow import Flow, control_flow_analysis
from utils.utils import match_str, match_pair, support_check


class PhpRootNode:
    def __init__(self, nodes):
        self.name = 'root'
        self.nodes = nodes


class FunctionInfo:
    """
    func_name:str
    func_type:phpast object
    father_list:[{"name": 'func_name', "type": func_type}, ...]
    node_ast:ast
    code:str
    file:str
    callers : []
    """

    def __init__(self, func_name, func_type, father_list, node_ast, code, file):
        self.func_name = func_name
        self.func_type = func_type
        self.father_list = father_list
        self.node_ast = node_ast
        self.code = code
        self.file = file
        self.callers = []

        # process
        self.code_split = code.split('\n')

    def set_lineno(self, start_lineno, end_lineno, code_line):
        self.start_lineno = start_lineno
        self.end_lineno = end_lineno
        self.code_line = code_line

    def set_callers(self, caller):
        self.callers.append(caller)

    def set_control_flow(self, flow):
        self.control_flow = flow

    def set_code_line_position(self, file):

        for i, code in enumerate(self.code_split):
            if i >= len(self.code_line):
                logger.warning("[ERROR] func_call.set_code_line_position(): code_line error")

            lineno = self.code_line[i]['lineno']
            sp = len('\n'.join(file.code_content[:lineno-1]))
            if lineno > 1:
                sp += 1
            ep = sp + len(code) + 1
            self.code_line[i]['position'] = (sp, ep)
            self.code_line[i]['code'] = code

    def get_code_by_lineno(self, lineno):
        for code_line in self.code_line:
            if code_line['lineno'] == lineno:
                return code_line


class FileInfo:
    """
    function_list:[]
    include_list:[]
    file_path:str
    """

    def __init__(self, file_path, target_directory):
        # output
        self.function_list = []
        self.include_list = []
        self.call_list = []

        # input
        self.file_path = file_path
        self.target_directory = target_directory

        # process
        self.__file_process()

    def __file_process(self):
        file = codecs.open(self.target_directory + self.file_path, "r", encoding='utf-8', errors='ignore')

        # code format change
        code = file.read()
        code = check_comment(code)
        self.code_content = code.split('\n')
        self.full_code = code
        file.close()


class OneCall:
    """
    called function: FunctionInfo
    call type: method or function
    ast: call ast node
    """

    def __init__(self, function, type, node, father_call):
        self.function = function
        self.type = type
        self.ast = node
        self.father_call = father_call


class CallStatement:
    """
    callers:[] OneCall
    statement: #code content
    ast:  #statement ast node
    lineno: int
    func_location:  # in which funcion in self.function_list
    file_location:  # in which file in self.file_list
    """

    def __init__(self, callers, statement, ast, lineno, func_location, file_location):
        self.callers = callers
        self.statement = statement
        self.ast = ast
        self.lineno = lineno
        self.func_location = func_location
        self.file_location = file_location


class FuncCall:
    """
    self.call_graph:list+
    """

    def __init__(self, target_directory, files):
        # output
        self.function_list = []
        self.call_list = []

        # input
        self.target_directory = target_directory
        self.files = files

        # processing
        self.__file_process()

    def __file_process(self):
        self.file_list = []
        self.pfa = FileParseAll(self.files, self.target_directory)

        leng = int(len(self.pfa.t_filelist)/20) + 19
        split_lists = [self.pfa.t_filelist[x: x + leng] for x in range(0, len(self.pfa.t_filelist), leng)]

        logger.info('[FUNC_CALL][INFO] Reading files... ')
        threading_list = []
        for i, f_list in enumerate(split_lists):
            t = threading.Thread(target=self.__fileinfo_save(f_list))
            t.start()
            threading_list.append(t)
        for t in threading_list:
            t.join()

        ast_object.init_pre(self.target_directory, self.files, self.file_list)
        ast_object.pre_ast_all("php", is_unprecom=False)

    def __fileinfo_save(self, f_list):
        for file in f_list:
            fi = FileInfo(file, self.target_directory)

            if not support_check(fi.full_code):
                continue
            self.file_list.append(fi)

    def main(self, analysis_mode="test"):
        """
        function call collection
        analysis_mode:train or test
        """
        logger.info("[INFO] Collecting functions...")
        for file in tqdm(self.file_list):
            ast_object.clear_none_node(file.file_path)
            nodes = ast_object.get_nodes(file.file_path)

            if not nodes:
                continue

            # collection function information
            # add root zone code as a function
            self.init_function_list(nodes, file)
            self.analysis_functions(nodes, [{"name": 'root', "type": None}], file, isroot=True)
            self.function_list += file.function_list

        if analysis_mode != 'test':
            # function call analysis
            logger.info("[INFO] Collecting function calls...")
            for file in tqdm(self.file_list):
                nodes = ast_object.get_nodes(file.file_path)

                if not nodes:
                    continue

                self.analysis_call(nodes, [{"name": 'root', "type": None}], file)

            # save caller to function
            self.gen_call_graph()

        # control flow of every function
        logger.info("[INFO] Generating control flows...")
        for func in tqdm(self.function_list):
            try:
                base_flow = Flow("base", [], func.start_lineno)
                isset = base_flow.set_base_flow(func.node_ast.nodes, func)
                if not isset:
                    continue
                func.set_control_flow(control_flow_analysis(func.node_ast.nodes, base_flow, func))
            except Exception as e:
                continue
        return



    def gen_call_graph(self):
        for call_stmt in self.call_list:
            for oc in call_stmt.callers:
                for func in self.function_list:
                    if func == oc.function:
                        func.set_callers(call_stmt)


    def analysis_call(self, nodes, father_list, file, stmt_node=None):
        """
        get all FunctionCall/MethodCall
        about to complete
        """
        for i, node in enumerate(nodes):
            if not isinstance(node, php.Node):
                continue

            # args prepare
            if hasattr(node, "name"):
                new_node_name = node.name
            else:
                new_node_name = node.__class__.__name__
            new_node_type = node.__class__.__name__
            newlineno = node.lineno

            is_recursion = False
            # different statement situation
            # compare expr
            if isinstance(node, php.If) or isinstance(node, php.ElseIf) \
                    or isinstance(node, php.DoWhile) or isinstance(node, php.Foreach) or isinstance(node, php.While) \
                    or isinstance(node, php.Switch) or isinstance(node, php.Case):
                self.single_line_call_collect(node.expr, father_list, newlineno, file, stmt_type="expr")
                is_recursion = True

            # assignment expr
            elif isinstance(node, php.Assignment) or isinstance(node, php.ListAssignment):
                self.single_line_call_collect(node, father_list, newlineno, file, stmt_type="assign")
                is_recursion = True

            # Op
            elif isinstance(node, php.AssignOp):
                self.single_line_call_collect(node, father_list, newlineno, file, stmt_type="op")
                is_recursion = True

            # direct function call
            elif isinstance(node, php.FunctionCall) or isinstance(node, php.MethodCall) or isinstance(node,
                                                                                                      php.StaticMethodCall):
                self.single_line_call_collect(node, father_list, newlineno, file, stmt_type="call")
                is_recursion = True

            elif isinstance(node, php.Block) or isinstance(node, php.Echo) or isinstance(node, php.Print):
                is_recursion = True

            # Scope zone
            if isinstance(node, php.Class) or isinstance(node, php.Function) or isinstance(node, php.Method):
                new_father_list = copy.deepcopy(father_list)
                new_father_list.append({"name": new_node_name, "type": new_node_type})
                is_recursion = True


            new_father_list = father_list

            # next node
            if is_recursion:
                if hasattr(node, "node"):
                    new_nodes = [node.node]
                    self.analysis_call(new_nodes, new_father_list, file)
                if hasattr(node, "nodes"):
                    new_nodes = node.nodes
                    self.analysis_call(new_nodes, new_father_list, file)
                if hasattr(node, "elseifs") and node.elseifs:
                    new_nodes = node.elseifs
                    self.analysis_call(new_nodes, new_father_list, file)
                if hasattr(node, "else_") and node.else_:
                    new_nodes = [node.else_.node]
                    self.analysis_call(new_nodes, new_father_list, file)

        return

    def single_line_call_collect(self, node, father_list, lineno, file, stmt_type="expr"):
        """
        stmt_type:
            1. expr: If, ElseIf, While, DoWhile, Foreach, Switch, Case.
                    e.g. If ( expr ) {...
            2. assign: Assignment, ListAssignment
                    e.g. $a = expr ;
            3. call: FunctionCall, MethodCall
                    e.g. print("<...>) ;
        """
        # get expr
        father_call = None
        tem_node = node
        root_node = node
        if stmt_type == 'assign':
            tem_node = node.expr

        # find Function call
        function_call_list_in_stmt = []

        # queue for node
        q = queue.Queue()
        q.put((tem_node, father_call))
        while not q.empty():
            tem = q.get()
            (node, father_call) = tem

            # judge is function call
            if isinstance(node, php.FunctionCall) or isinstance(node, php.MethodCall) or isinstance(node, php.StaticMethodCall):
                class_name = None
                if isinstance(node, php.StaticMethodCall):
                    class_name = str(node.class_)
                func = self.func_match(node, node.__class__.__name__, father_list, file, class_name)
                if func:
                    one_call = OneCall(func, node.__class__.__name__, node, father_call)
                    function_call_list_in_stmt.append(one_call)
                    father_call = one_call

            # add to queue
            if hasattr(node, "node") and node.node:
                new_node = node.node
                q.put((new_node, father_call))
            if hasattr(node, "nodes") and node.nodes:
                new_nodes = node.nodes
                for n in new_nodes:
                    q.put((n, father_call))
            if hasattr(node, "left") and node.left:
                new_node = node.left
                q.put((new_node, father_call))
            if hasattr(node, "right") and node.right:
                new_node = node.right
                q.put((new_node, father_call))
            if hasattr(node, "expr") and node.expr:
                new_node = node.expr
                q.put((new_node, father_call))
            if hasattr(node, "params") and node.params:
                new_nodes = node.params
                for n in new_nodes:
                    if n.__class__.__name__ == "Parameter":
                        q.put((n.node, father_call))

        # save statement with call
        if len(function_call_list_in_stmt):
            statement = file.code_content[lineno - 1]
            ast = root_node
            func_location = father_list
            file_location = file
            callstmt = CallStatement(function_call_list_in_stmt, statement, ast, lineno, func_location, file_location)

            self.call_list.append(callstmt)




    def func_match(self, node, type, father_list, file, class_name=None, class_=None):
        """
        match functionCall with function in self.function_list
        """
        father_list = father_list[:-1]
        func_call_name = node.name
        if "Method" in type:
            type = "Method"
        else:
            type = "Function"

        same_name_func = []
        for func in file.function_list:
            if func.func_name == func_call_name and type == func.func_type and func.func_name != '__construct':
                same_name_func.append(func)

        # analysis which function can functioncall  access
        if len(same_name_func) == 1:
            return same_name_func[0]
        elif len(same_name_func) > 1 and len(same_name_func) <=3:
            logger.warning(
                "[WARNING] function match multy result:\n\t\t\trealm: {}, \n\tfunction name:".format(father_list,same_name_func[0].func_name))
            result_func = None
            for func in same_name_func:
                if result_func == None:
                    result_func = func
                    continue

                match = True

                for i in range(min(len(father_list), len(func.father_list))):
                    if father_list[i]["name"] != func.father_list[i]["name"] or father_list[i]["type"] != \
                            func.father_list[i]["type"]:
                        match = False
                        break
                if not match:
                    if class_name == "parent":
                        result_func = func
                        break
                if match:
                    if class_name != "parent":
                        result_func = func
                        break
                    else:
                        continue

                if len(result_func.father_list) > len(func.father_list):
                    result_func = func

            if result_func == None:
                logger.error("[ERROR] function match error: 1")

            return result_func
        elif len(same_name_func) >3:
            return None
        else:
            # include
            include_files = file.include_list
            tem_func_list = []
            for f in include_files:
                if f.expr == file.file_path:
                    continue
                else:
                    for self_file in self.file_list:
                        if self_file.file_path == f.expr:
                            tem_func_list += self_file.function_list
                            break

            for func in tem_func_list:
                if func.func_name == func_call_name:
                    same_name_func.append(func)

            if len(same_name_func) == 1:
                return same_name_func[0]
            elif len(same_name_func) > 1:
                logger.error("[ERROR] function match error: 2")

            else:
                # build in function
                find_buildin = False
                for func in BUILTIN_FUNC:
                    if func_call_name == func:
                        find_buildin = True
                        break
                if find_buildin:
                    #         return FunctionInfo(func, "build_in", [], None, None, None)
                    # logger.debug(
                    #     "[DEBUG] function match found buildin: {} in file: {}".format(func_call_name, file.file_path))
                    return None
                else:
                    # logger.error(
                    #     "[Warning] function match not found: {} in file: {}".format(func_call_name, file.file_path))
                    return None

    def init_function_list(self, nodes, file):
        """
        treat root code content as a function without title
        add to function_list
        """
        new_nodes = []
        new_code = "\n".join(file.code_content[:nodes[0].lineno - 1])
        code_line = [{'lineno':i + 1, 'position':None} for i in range(nodes[0].lineno - 1)]
        end_lineno = nodes[0].lineno - 1

        for i, node in enumerate(nodes):
            next_node = None
            if i + 1 >= len(nodes):
                next_lineno = len(file.code_content) + 1
            else:
                next_node = nodes[i + 1]
                if next_node:
                    next_lineno = next_node.lineno
                else:
                    logger.error("[ERROR] func_call.init_function_list(): 1")



            start_pos = node.lineno - 1
            if not next_node:
                if start_pos == 0:
                    new_code += "\n".join(file.code_content[start_pos:])
                else:
                    new_code += "\n" + "\n".join(file.code_content[start_pos:])
            else:
                end_pos = next_node.lineno - 1
                if end_pos>start_pos:
                    if start_pos == 0:
                        new_code += "\n".join(file.code_content[start_pos:end_pos])
                    else:
                        new_code += "\n" + "\n".join(file.code_content[start_pos:end_pos])
            for l in range(node.lineno, next_lineno):
                code_line.append({'lineno':l, 'position':None})
            end_lineno = len(file.code_content)
            new_nodes.append(node)

        # prepare root function/method information
        root_function_info = FunctionInfo("root", None, [], PhpRootNode(new_nodes), new_code, file.file_path)
        root_function_info.set_lineno(1, end_lineno, code_line)
        root_function_info.set_code_line_position(file)
        file.function_list.append(root_function_info)

    def analysis_functions(self, nodes, father_list, file, isroot=False):
        """
        get all function, Method
        """

        for i, node in enumerate(nodes):
            # collection include/require node
            if isinstance(node, php.Include) or isinstance(node, php.Require):
                if node.expr.__class__.__name__ == "str":
                    file.include_list.append(node)

            if hasattr(node, "name"):
                new_node_name = node.name
            else:
                new_node_name = node.__class__.__name__
            new_node_type = node.__class__.__name__

            if isinstance(node, php.Class) or isinstance(node, php.Function) or isinstance(node, php.Method):
                if not isinstance(node, php.Class):
                    # prepare code of function/method
                    next_node = None
                    if i + 1 < len(nodes):
                        next_node = nodes[i + 1]

                    node_code, start_line, end_lineno, code_line = self.get_func_code(node, next_node, file)

                    # prepare function/method information
                    function_info = FunctionInfo(new_node_name, new_node_type, father_list, node, node_code,
                                                 file.file_path)
                    function_info.set_lineno(start_line, end_lineno, code_line)
                    function_info.set_code_line_position(file)
                    file.function_list.append(function_info)

                new_father_list = copy.deepcopy(father_list)
                new_father_list.append({"name": new_node_name, "type": new_node_type})

            else:
                new_father_list = father_list

            if hasattr(node, "node"):
                new_nodes = [node.node]
                self.analysis_functions(new_nodes, new_father_list, file)
            if hasattr(node, "nodes"):
                new_nodes = node.nodes
                self.analysis_functions(new_nodes, new_father_list, file)
            if hasattr(node, "elseifs") and node.elseifs:
                new_nodes = node.elseifs
                self.analysis_functions(new_nodes, new_father_list, file)
            if hasattr(node, "else_") and node.else_:
                new_nodes = [node.else_.node]
                self.analysis_functions(new_nodes, new_father_list, file)
            else:
                continue
                # logger.error("[ERROR] node has node attr node/nodes, node: {}  {}".format(new_node_name, new_node_type))

        return

    def get_func_code(self, node, next_node, file):
        """
        get code content of function
        """
        start_lineno = node.lineno - 1
        last_lineno = -1
        if next_node:
            last_lineno = next_node.lineno - 1

            func_code = '\n'.join(file.code_content[start_lineno:last_lineno])
            code_line = [{'lineno':start_lineno + 1 + i, 'position':None} for i in range(last_lineno - start_lineno)]
            return func_code, start_lineno + 1, last_lineno + 1, code_line
        else:
            func_code = '\n'.join(file.code_content[start_lineno:])

        # last node
        tem_code = func_code[match_str(func_code, '{'):]
        last_pos = match_str(func_code, '{') + 1
        lr_pos = match_pair(tem_code, '{', '}')
        if not lr_pos:
            logger.error("[ERROR] get_func_code(): iter error, code: {}".format(tem_code))


        last_pos += lr_pos[1]

        func_code = func_code[:last_pos]
        last_lineno = start_lineno
        code_line = []
        for i in range(len(func_code.split('\n'))):
            last_lineno += 1
            code_line.append({'lineno':last_lineno, 'position':None})

        return func_code, start_lineno + 1, last_lineno, code_line


