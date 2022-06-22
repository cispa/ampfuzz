#!/usr/bin/env python3
# coding: utf-8

import json
import glob
import random
import re
import os

class DebugInfo:
    def __init__(self, llpath):
        with open(llpath) as f:
            self.assembly = f.read().splitlines()

    
    def find_attrib_id(self, branch_id):
        # attributes are stored towards the end, so we iterate in reverse for faster matching
        attrib_re = re.compile(r'!(?P<attrib_id>\d+)\s*=\s*!\{i64\s*(?P<ins_id>-?\d+)\}')
        for line in reversed(self.assembly):
            if not line.startswith('!'):
                continue
            m = attrib_re.fullmatch(line)
            if m:
                ins_id = int(m.group('ins_id'))
                if ins_id % (1<<32) == branch_id:
                    return int(m.group('attrib_id'))
        raise ValueError(f'Could not find attrib_id for branch_id {branch_id}')
                    
    def find_assembly_line(self, instruction_id_attrib_id):
        ptn = f'!instruction_id !{instruction_id_attrib_id}'
        for i, line in enumerate(self.assembly):
            if ptn in line:
                return i, line
        raise ValueError(f'Could not find assembly_line for instruction_id_attrib_id {instruction_id_attrib_id}')
                
    def find_dbg_id(self, line_num):
        dbg_re = re.compile(r'!dbg\s*!(?P<attrib_id>\d+)\s*')
        for line in reversed(self.assembly[:line_num+1]):
            if '!dbg' not in line:
                continue
            m = dbg_re.search(line)
            if m:
                return int(m.group('attrib_id'))
        raise ValueError(f'Could not find dbg_id for line {line_num}')

    def get_attrib_info(self, attrib_id):
        ptn = f'!{attrib_id}'
        for line in reversed(self.assembly):
            if line.strip().startswith(ptn):
                return line
        raise ValueError(f'Could not find attrib_id {attrib_id}')
 
    def get_debug_info(self, attrib_id):
        attrib_info = self.get_attrib_info(attrib_id)
        if '!DILocation(' in attrib_info:
            line = None
            column = None
            scope = None
            for tok in attrib_info.split('!DILocation', maxsplit=1)[1].strip().strip('()').split(','):
                k,v = (x.strip() for x in tok.strip().split(':'))
                if k=='line':
                    line = int(v)
                elif k=='column':
                    column = int(v)
                elif k=='scope':
                    scope = self.get_debug_info(int(v.lstrip('!')))
            return f'line {line}, col {column} in {scope}'
        elif '!DILexicalBlock(' in attrib_info:
            scope = None
            for tok in attrib_info.split('!DILexicalBlock', maxsplit=1)[1].strip().strip('()').split(','):
                k,v = (x.strip() for x in tok.strip().split(':'))
                if k=='scope':
                    scope = self.get_debug_info(int(v.lstrip('!')))
            return scope
        elif '!DISubprogram(' in attrib_info:
            name = None
            file = None
            for tok in attrib_info.split('!DISubprogram', maxsplit=1)[1].strip().strip('()').split(','):
                 k,v = (x.strip() for x in tok.strip().split(':'))
                 if k=='name':
                     name = v.strip('"\'')
                 elif k=='file':
                     file = self.get_debug_info(int(v.lstrip('!')))
            return f'function \'{name}\' in {file}'
        elif '!DIFile(' in attrib_info:
            filename = None
            directory = None
            for tok in attrib_info.split('!DIFile', maxsplit=1)[1].strip().strip('()').split(','):
                k,v = (x.strip() for x in tok.strip().split(':'))
                if k=='filename':
                    filename = v.strip('"\'')
                elif k=='directory':
                    directory = v.strip('"\'')
            return os.path.normpath(os.path.join(directory, filename) if directory else filename)
        return '?'
        
    def get_debug_info_for_branch_id(self, branch_id):
        try:
            return self.get_debug_info(self.find_dbg_id(self.find_assembly_line(self.find_attrib_id(branch_id))[0]))
        except ValueError:
            return '??'

THRESH=.5

def c(i,n):
    h = i/n
    return f'{h:.3} 1.000 1.000'
    
nodes = dict() # mapping from (branch_id, taken, mult) to node_name
edges = dict() # mapping from node_name to node_name to list of colors

def get_node(branch_id, taken, mult):
    key = (branch_id, taken, mult)
    if key not in nodes:
        node_id = len(nodes)
        node_name = f'node_{node_id}'
        nodes[key] = node_name
    return nodes[key]
    
def parse_raw(raw_trace):
    COND_LEN_OP = 0x8003

    threads = dict()
    for event in raw_trace:
        if 'base' not in event:
            continue
        base = event['base']
        if not base['lb1'] and not base['lb2'] and not base['op'] == COND_LEN_OP:
            continue
        tid = base.get('tid', 0)
        if tid not in threads:
            threads[tid] = list()
        threads[tid].append(base)
    return [[(b['cmpid'], (b['condition'], b['order']>>16)) for b in thread] for thread in threads.values()]

def handle_trace(trace_file, color, collapse=False):
    with open(trace_file) as f:
        trace_raw = json.load(f)
    trace = parse_raw(trace_raw)
    for thread in trace:
        counts = dict()
        thread_nodes = []
        for branch_id, taken in thread:
            mult = counts.get((branch_id, taken), 0) if not collapse else 0
            thread_nodes.append(get_node(branch_id, taken, mult))
            counts[(branch_id, taken)] = mult+1
        for a,b in zip(['start']+thread_nodes, thread_nodes+['end']):
            edge_dict = edges.get(a, dict())
            color_list = edge_dict.get(b, list())
            color_list.append(color)
            edge_dict[b] = color_list
            edges[a] = edge_dict

            
def dump_nodes(di):
    branch_id_colors=dict()
    branch_ids = sorted(set(k[0] for k in nodes.keys()))
    random.seed(1337)
    random.shuffle(branch_ids)
    for i, branch_id in enumerate(branch_ids):
        branch_id_colors[branch_id] = c(i, len(branch_ids))

    for k,v in nodes.items():
        branch_id = k[0]
        color = branch_id_colors[branch_id]
        dbg_label = di.get_debug_info_for_branch_id(branch_id)
        yield f"{v} [label=<{k}<BR/>{dbg_label.replace(' in ','<BR/>')}> style=\"radial\" fillcolor=\"0.000 0.000 1.000:{color}\"]"

def dump_edges():
    for a, bs in edges.items():
        for b, cs in bs.items():
            for c in cs:
                yield f"{a} -> {b} [color=\"{c}\"]"

def simplify_edges():
    for a in edges.keys():
        if len(edges[a]) == 1: 
            # only a single output-edge? replace all arrows by a single black arrow
            b = next(iter(edges[a].keys()))
            edges[a] = {b: ['0.000 0.000 0.000']}
        else:
            # multiple output-edge? if there is one path that is taken by more than THRESH of the eges, replace it with a black arrow
            num_out_edges = sum(len(cs) for cs in edges[a].values())
            threshold_edges = int(THRESH*num_out_edges)
            for b in edges[a].keys():
                if len(edges[a][b]) > threshold_edges:
                    edges[a][b] = ['0.000 0.000 0.000']
        
def main():

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('unfoldll')
    parser.add_argument('-c','--collapse', action='store_true')
    args = parser.parse_args()

    di = DebugInfo(args.unfoldll)

    traces = sorted(file for file in glob.glob('*.json') if not file.endswith('_trace.json'))
    trace_paths = []
    for i, trace in enumerate(traces):
        handle_trace(trace, c(i, len(traces)), collapse=args.collapse)

    simplify_edges()

    print('digraph G{')
    for node_info in dump_nodes(di):
        print(f'\t{node_info}')
    for edge in dump_edges():
        print(f'\t{edge}')
    print('}')

if __name__ == '__main__':
    main()
