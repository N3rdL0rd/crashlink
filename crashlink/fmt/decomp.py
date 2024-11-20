from ..core import *
from . import disasm
from ..errors import *
from ..opcodes import opcodes
import traceback

class CFNode:
    """
    A control flow node.
    """
    
    def __init__(self, ops: List[Opcode]):
        self.ops = ops
        self.branches = []

    def __repr__(self):
        return "<CFNode: %s>" % self.ops
    
class CFGraph:
    """
    A control flow graph.
    """
    
    def __init__(self, func: Function):
        self.func = func
        self.nodes = []
        self.entry = None
    
    def add_node(self, ops: List[Opcode]) -> CFNode:
        node = CFNode(ops)
        self.nodes.append(node)
        return node
    
    def add_branch(self, src: CFNode, dst: CFNode, edge_type: str):
        src.branches.append((dst, edge_type))
    
    def build(self):
        """Build the control flow graph."""
        if not self.func.ops:
            return
    
        jump_targets = set()
        for i, op in enumerate(self.func.ops):
            if op.op in ["JTrue", "JFalse", "JNull", "JNotNull", 
                        "JSLt", "JSGte", "JSGt", "JSLte",
                        "JULt", "JUGte", "JNotLt", "JNotGte",
                        "JEq", "JNotEq", "JAlways"]:
                jump_targets.add(i + op.definition["offset"].value + 1)
    
        current_ops = []
        current_start = 0
        blocks = []  # (start_idx, ops) tuples
        
        for i, op in enumerate(self.func.ops):
            if i in jump_targets and current_ops:
                blocks.append((current_start, current_ops))
                current_ops = []
                current_start = i
                
            current_ops.append(op)
            
            if op.op in ["JTrue", "JFalse", "JNull", "JNotNull",
                        "JSLt", "JSGte", "JSGt", "JSLte", 
                        "JULt", "JUGte", "JNotLt", "JNotGte",
                        "JEq", "JNotEq", "JAlways", "Ret"]:
                blocks.append((current_start, current_ops))
                current_ops = []
                current_start = i + 1
    
        if current_ops:
            blocks.append((current_start, current_ops))
    
        nodes_by_idx = {}
        for start_idx, ops in blocks:
            node = self.add_node(ops)
            nodes_by_idx[start_idx] = node
            if start_idx == 0:
                self.entry = node
    
        for start_idx, ops in blocks:
            src_node = nodes_by_idx[start_idx]
            last_op = ops[-1]
            
            next_idx = start_idx + len(ops)
            
            # conditionals
            if last_op.op in ["JTrue", "JFalse", "JNull", "JNotNull",
                            "JSLt", "JSGte", "JSGt", "JSLte",
                            "JULt", "JUGte", "JNotLt", "JNotGte", 
                            "JEq", "JNotEq"]:
                
                jump_idx = start_idx + len(ops) + last_op.definition["offset"].value
                
                # - Jump target is "true" branch
                # - Fall-through is "false" branch
                    
                # Handle jump target
                if jump_idx in nodes_by_idx:
                    edge_type = "true"
                    self.add_branch(src_node, nodes_by_idx[jump_idx], edge_type)
                    
                if next_idx in nodes_by_idx:
                    edge_type = "false" 
                    self.add_branch(src_node, nodes_by_idx[next_idx], edge_type)
                    
            # unconditionals
            elif last_op.op == "JAlways":
                jump_idx = start_idx + len(ops) + last_op.definition["offset"].value
                if jump_idx in nodes_by_idx:
                    self.add_branch(src_node, nodes_by_idx[jump_idx], "unconditional")
            elif last_op.op != "Ret" and next_idx in nodes_by_idx:
                self.add_branch(src_node, nodes_by_idx[next_idx], "unconditional")
    
    def graph(self, code: Bytecode):
        """Generate DOT format graph visualization."""
        dot = ['digraph G {']
        dot.append('  node [shape=box, fontname="Courier"];')
        dot.append('  edge [fontname="Courier"];')
        
        for node in self.nodes:
            label = '\n'.join([
                disasm.pseudo_from_op(op, i, self.func.regs, code)
                for i, op in enumerate(node.ops)
            ]).replace('"', '\\"').replace('\n', '\\n')
            
            style = 'style=filled, fillcolor=darkolivegreen1' if node == self.entry else 'style=filled, fillcolor=lightblue'
            dot.append(f'  node_{id(node)} [label="{label}", {style}];')
        
        for node in self.nodes:
            for branch, edge_type in node.branches:
                if edge_type == "true":
                    style = 'color="green", label="true"'
                elif edge_type == "false":
                    style = 'color="crimson", label="false"'
                else:  # unconditional
                    style = 'color="cornflowerblue"'
                    
                dot.append(f'  node_{id(node)} -> node_{id(branch)} [{style}];')
        
        dot.append('}')
        return '\n'.join(dot)