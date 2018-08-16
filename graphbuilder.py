from disassembler import Disassembler
from interpreter import BasicInterpreter
from image import Image
from structures import ExternalFunction
from opcodes import exit_ops
from resolver import BasicResolver


import sys, os

FALLBACK_SIGNATURE = 0xffffffff


class GraphBuilder(Disassembler):
	def __init__(self, binary):
		Disassembler.__init__(self, binary)
		self.__init_resolver()
		# initial build of graph
		self.__build_graph(self.get_blocks())
		self.__mark_signature_blocks()
		# simplify graph
		self.graph.simplify(self.__signature_blocks, self.resolver)
		# build again because we need the indirect jumps
		self.__build_graph(self.graph.get_blocks())

		self.__create_external_functions()
		self.__create_fallback_function()

	def __init_resolver(self):
		self.resolver = BasicResolver(self.jump_dests)
		for block in self.get_blocks().values():
			exit_bytecode = block.get_exit_bytecode()
			opcode = exit_bytecode.opcode
			if opcode in exit_ops | {"JUMP"}:
				continue
			block_id = block.get_id()
			suc_id = block_id + 1
			self.resolver.set_natural_successor(block_id, suc_id)

	def __build_graph(self, blocks):
		interpreter = BasicInterpreter(blocks, self.resolver)
		self.graph, self.tracker = \
			interpreter.explore_control_flow_graph(0, Image(-1))
		self.indirect_jumps = interpreter.ambiguous_blocks

	# def __simplify_graph(self):
	# 	change = True
	# 	while change:
	# 		removed = set()
	# 		for block_id, block in self.graph.get_blocks().items():
	# 			if block_id in removed:
	# 				continue
	# 			suc_id = self.__can_merge(block_id)
	# 			if suc_id is None:
	# 				continue
	# 			if block_id in self.__signature_blocks:
	# 				continue
	# 			suc_block = self.graph[suc_id]
	# 			block.merge(suc_block)
	# 			# print(block_id, suc_id)
	#
	# 			self.graph.remove_edge(block_id, suc_id)
	# 			suc_ids = self.graph.get_successor_ids(suc_id)
	# 			for i in suc_ids:
	# 				self.graph.add_edge(block_id, i)
	#
	# 			self.graph.remove_block(suc_id)
	# 			removed.add(suc_id)
	#
	# 			nas = self.resolver.get_natural_successor(suc_id)  # don't care if none
	# 			self.resolver.set_natural_successor(block_id, nas)
	# 		change = len(removed) != 0
	#
	# def __can_merge(self, block_id):
	# 	suc_ids = self.graph.get_successor_ids(block_id)
	# 	if len(suc_ids) != 1:
	# 		return None
	# 	suc_id = suc_ids.pop()
	# 	if len(self.graph.get_predecessor_ids(suc_id)) != 1:
	# 		return None
	# 	return suc_id

	def __mark_signature_blocks(self):
		self.__signature_blocks = dict()
		for block in self.graph.get_blocks().values():
			signature = block.get_function_signature()
			if signature != -1:
				self.__signature_blocks[block.get_id()] = signature

	def __create_external_functions(self):
		self.external_functions = dict()
		for cur_id, signature in self.__signature_blocks.items():
			func = self.__create_external_function(cur_id, signature)
			self.external_functions[signature] = func
		# func.visualize_function()

	def __create_external_function(self, cur_id, signature):
		entry_ids = self.graph.get_successor_ids(cur_id)
		entry_id = max([int(i) for i in entry_ids])

		interpreter = BasicInterpreter(self.graph.get_blocks(), self.resolver)

		image = self.tracker.get_observed_image(entry_id)
		graph, trackers = interpreter.explore_control_flow_graph(entry_id, image)
		f = ExternalFunction(signature, graph, trackers, (entry_id, None))
		# f.indirect_jumps = interpreter.ambiguous_blocks
		return f

	def __create_fallback_function(self):
		if len(self.__signature_blocks) == 0:
			func = ExternalFunction(FALLBACK_SIGNATURE, self.graph, self.tracker, (0, None))
			self.external_functions[FALLBACK_SIGNATURE] = func
		else:
			suc_ids = self.graph.get_successor_ids(0)
			suc_ids = suc_ids - set(self.__signature_blocks.keys())
			if len(suc_ids) == 1:
				if 0 not in self.__signature_blocks:
					func = self.__create_external_function(0, FALLBACK_SIGNATURE)
					self.external_functions[FALLBACK_SIGNATURE] = func
		# this sucks
		if FALLBACK_SIGNATURE not in self.external_functions:
			if not self.graph.has_block(1):
				self.graph.add_block(self.get_blocks()[1])
			func = ExternalFunction(FALLBACK_SIGNATURE, self.graph, self.tracker, (1, None))
			self.external_functions[FALLBACK_SIGNATURE] = func

	def validate_execution_path(self, program_counters):
		path = self.get_block_trace(program_counters)
		# print(path)
		self.graph.validate_path_exists(path)

	def visualize_contract(self, out_file="out_contract"):
		self.graph.visualize("temp/temp.dot")
		os.system("dot -Tpdf temp/temp.dot -o %s" % out_file)

	def debug_function_bytecodes(self):
		for func in self.external_functions.values():
			func.debug_function()


if __name__ == "__main__":
	input_file = open(sys.argv[1])
	line = input_file.readline().strip()
	if " " in line:
		line = line.split(" ")[1]
	input_file.close()
	a = GraphBuilder(line)

	if "-v" in sys.argv:
		a.visualize_contract()
	if "-d" in sys.argv:
		a.debug_function_bytecodes()
