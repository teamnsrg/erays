from aggregator import Aggregator
from structures import *

import sys


class Structurer(Aggregator):
	def __init__(self, binary):
		Aggregator.__init__(self, binary)
		for func in self.get_all_functions():
			self.__analyze_function(func)

	def __analyze_function(self, func):
		# if func.signature != 0xd9f5aed:
		# 	return
		# func.visualize_function()

		graph = func.graph
		if self.__has_indirect_jumps(graph):
			return

		sorted_ids = graph.depth_first_search(func.entry_id)
		for block_id in sorted_ids:
			self.__match_structures(block_id, graph)

		entry_id = func.entry_id
		for block in graph:
			result = block.get_block(entry_id)
			if result is not None:
				func.entry_id = block.get_id()

		func.visualize_function()

	def __has_indirect_jumps(self, graph):
		indirect_jumps = set()
		for block in graph:
			block_id = block.get_id()
			if block.check_exit_expression("JUMP") \
				and len(graph.get_successor_ids(block)) > 1:
				indirect_jumps.add(block_id)
		return len(indirect_jumps) != 0

	def __match_structures(self, block_id, graph):
		if not graph.has_block(block_id):
			return
		original_id, cur_id = block_id, -1
		while cur_id != block_id:
			cur_id = block_id
			block_id = self.__match_ifthen(block_id, graph)
			block_id = self.__match_sequence(block_id, graph)
			block_id = self.__match_ifthenelse(block_id, graph)
			block_id = self.__match_loop(block_id, graph)

	def __match_sequence(self, a0, graph):
		sequence = [a0]
		prev_id = a0
		while True:
			cur_id = graph.get_single_successor(prev_id)
			if cur_id is None:
				break
			if graph.get_single_predecessor(cur_id) != prev_id:
				break
			if graph.has_edge(cur_id, prev_id):
				break
			sequence.append(cur_id)
			prev_id = cur_id
		# print(sequence)
		if len(sequence) == 1:
			return a0
		an = sequence[-1]
		new_id = graph.allocate_id()
		blocks = [graph[i] for i in sequence]
		block = Seq(new_id, graph[an].get_exit_address(), blocks)
		graph.add_block(block)

		graph.transfer_predecessors(a0, new_id)
		graph.transfer_successors(an, new_id)

		graph.remove_blocks(sequence)
		return a0

	def __match_ifthen(self, a0, graph):
		suc_ids = graph.get_dual_successors(a0)
		if suc_ids is None:
			return a0
		a1 = graph.get_natural_successor(a0)
		a2 = graph.get_single_successor(a1)
		if a2 not in suc_ids:
			return a0

		new_id = graph.allocate_id()
		block = IfThen(new_id, graph[a2].get_entry_address(), graph[a0], graph[a1])
		graph.add_block(block)
		graph.transfer_predecessors(a0, new_id)
		graph.remove_blocks({a0, a1})
		graph.add_edge(new_id, a2)
		return new_id

	def __match_ifthenelse(self, a0, graph):
		suc_ids = graph.get_dual_successors(a0)
		if suc_ids is None:
			return a0
		a1 = graph.get_natural_successor(a0)
		a2 = (suc_ids - {a1}).pop()
		if graph.get_single_predecessor(a1) != graph.get_single_predecessor(a2):
			return a0
		a3 = graph.get_single_successor(a1)
		if a3 is None or a3 != graph.get_single_successor(a2):
			return a0
		suc_address = graph[a3].get_entry_address()
		new_id = graph.allocate_id()
		block = IfThenElse(new_id, suc_address, graph[a0], graph[a1], graph[a2])
		graph.add_block(block)
		graph.transfer_predecessors(a0, new_id)
		graph.add_edge(new_id, a3)
		graph.remove_blocks({a0, a1, a2})
		return new_id

	def __match_loop(self, a0, graph):
		suc_ids = graph.get_dual_successors(a0)
		if suc_ids is None:
			return a0
		a1, a2 = suc_ids
		if graph.get_single_successor(a2) == a0:
			a1, a2 = a2, a1
		if graph.get_single_successor(a1) != a0\
			or graph.get_single_predecessor(a1) != a0:
			return a0
		new_id = graph.allocate_id()
		suc_address = graph[a2].get_entry_address()
		block = Loop(new_id, suc_address, graph[a0], graph[a1])
		graph.add_block(block)
		graph.transfer_predecessors(a0, new_id)
		graph.add_edge(new_id, a2)
		graph.remove_blocks({a0, a1})
		return new_id

	def visualize_functions(self):
		for func in self.get_all_functions():
			func.visualize_function()


if __name__ == "__main__":
	input_file = open(sys.argv[1])
	line = input_file.readline().strip()
	if " " in line:
		line = line.split(" ")[1]
	input_file.close()
	a = Structurer(line)
	if "-v" in sys.argv:
		a.visualize_functions()