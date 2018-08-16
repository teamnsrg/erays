from instructions import to_stack_registers
from opcodes import INTERNAL_CALL_OPCODE
from expressionblock import ExpressionBlock

import os


def get_prefix(depth):
	return "  " * depth


class ExternalFunction(object):
	def __init__(self, signature, graph, tracker, entry_exit):
		self.signature = signature
		self.graph = graph
		self.tracker = tracker
		self.entry_id, self.exit_id = entry_exit
		self.resolver = None
		self.ins_outs = None

	def get_begin_address(self):
		# print(self.entry_id)
		entry_block = self.graph[self.entry_id]
		return entry_block.get_entry_address()

	def extract_intcall(self, callee_pair, caller_pair, opcode):
		callee_begin, callee_end = callee_pair
		caller_begin, caller_end = caller_pair

		caller_begin_block = self.graph[caller_begin]
		caller_end_block = self.graph[caller_end]

		new_block = \
			caller_begin_block.insert_intcall(opcode, caller_end_block)
		self.graph.replace_block(new_block)

		self.graph.remove_edge(caller_begin, callee_begin)
		self.graph.remove_edge(callee_end, caller_end)
		self.graph.add_edge(caller_begin, caller_end)

	# def convert_to_ssa(self):
	# 	self.__create_work_lists()
	# 	self.__insert_phi_functions()
	# 	self.__rename_registers()
	#
	# def __create_work_lists(self):
	# 	self.__work_lists = dict()
	# 	for basic_block in self.graph:
	# 		cur_id = basic_block.get_str_id()
	# 		for register in basic_block.exit_registers:
	# 			if register not in self.__work_lists:
	# 				self.__work_lists[register] = set()
	# 			self.__work_lists[register].add(cur_id)
	# 	return
	#
	# def __insert_phi_functions(self):
	# 	frontiers = self.graph.get_dominance_frontiers(self.entry_id)
	# 	for register, work_list in self.__work_lists.items():
	# 		while len(work_list) != 0:
	# 			cur_id_1 = work_list.pop()
	# 			frontier = frontiers[cur_id_1]
	# 			for cur_id_2 in frontier:
	# 				basic_block = self.graph[cur_id_2]
	# 				if basic_block.has_phi_function(register):
	# 					continue
	# 				pre_ids = self.graph.get_predecessor_ids(cur_id_2)
	# 				# (pre_id -> register) trivial phi function
	# 				basic_block.insert_phi_function(register, pre_ids)
	# 				work_list.add(cur_id_2)
	# 	return
	#
	# def __rename_registers(self):
	# 	self.__name_counter = {"$s0": 1, "$t": 0}
	# 	self.__name_stack = {"$s0": ["$s0_0"], "$t": []}
	#
	# 	for i in range(1, 40):
	# 		register = "$s" + str(i)
	# 		self.__name_counter[register] = 0
	# 		self.__name_stack[register] = []
	#
	# 	self.__dominator_tree = \
	# 		self.graph.get_dominator_tree(self.entry_id)
	# 	# print(self.__dominator_tree)
	# 	self.__rename_block_registers(self.entry_id)
	# 	return
	#
	# def __rename_block_registers(self, cur_id):
	# 	cur_block = self.graph[cur_id]
	# 	phi_functions = cur_block.phi_functions
	# 	to_pop = dict()
	#
	# 	for register in phi_functions.keys():
	# 		if register not in to_pop:
	# 			to_pop[register] = 0
	# 		to_pop[register] += 1
	# 		new_register = self.__get_new_name(register)
	# 		phi_functions[new_register] = phi_functions.pop(register)
	#
	# 	for instruction in cur_block:
	# 		for register in instruction.reads:
	# 			new_register = self.__get_top_name(register)
	# 			instruction.rename_read_register(register, new_register)
	# 		for register in instruction.writes:
	# 			if register not in to_pop:
	# 				to_pop[register] = 0
	# 			to_pop[register] += 1
	# 			new_register = self.__get_new_name(register)
	# 			instruction.rename_write_register(register, new_register)
	# 		# print(str(instruction).lower())
	# 	# self.debug_function_instructions(cur_id)
	# 	# TODO: is this even right?
	# 	for index, register in enumerate(cur_block.exit_registers):
	# 		new_register = self.__get_top_name(register)
	# 		cur_block.exit_registers[index] = new_register
	#
	# 	for suc_id in self.graph.get_successor_ids(cur_id):
	# 		suc_block = self.graph[suc_id]
	# 		for phi_function in suc_block.phi_functions.values():
	# 			for pre_id, register in phi_function.items():
	# 				if pre_id == cur_id:
	# 					new_register = self.__get_top_name(register)
	# 					# print(pre_id, register, new_register)
	# 					phi_function[pre_id] = new_register
	#
	# 	if cur_id not in self.__dominator_tree:
	# 		return
	#
	# 	for child_id in self.__dominator_tree[cur_id]:
	# 		self.__rename_block_registers(child_id)
	#
	# 	for register, count in to_pop.items():
	# 		for i in range(count):
	# 			self.__name_stack[register].pop()
	# 	return
	#
	# def __get_new_name(self, register):
	# 	count = self.__name_counter[register]
	# 	self.__name_counter[register] = count + 1
	# 	new_name = register + "_%d" % count
	# 	self.__name_stack[register].append(new_name)
	# 	return new_name
	#
	# def __get_top_name(self, register):
	# 	return self.__name_stack[register][-1]
	# def convert_to_expressions(self):
	# 	for basic_block in self.graph:
	# 		basic_block = ExpressionBlock(basic_block)
	#
	# 		basic_block.aggregate_expressions()
	# 		# basic_block.collapse_expressions()
	# 		basic_block.fold_expressions()
	# 		self.graph.replace_block(basic_block)

	def get_block_hashes(self):
		block_hashes = list()
		for basic_block in self.graph:
			block_hashes.append(basic_block.get_block_hash())
		return block_hashes

	def visualize_function(self):
		if not os.path.exists("temp/"):
			os.makedirs("temp/")
		self.graph.visualize("temp/temp.dot")
		os.system("dot -Tpdf temp/temp.dot -o temp/0x%x.pdf" % self.signature)

	def debug_function(self, block_id=None):
		if block_id:
			self.graph[block_id].debug_block()
			return
		print("\nfunction_" + hex(self.signature))
		for basic_block in self.graph:
			basic_block.debug_block(0)

	def __str__(self):
		return "function_%x" % self.signature


class InternalFunction(ExternalFunction):
	def __init__(self, signature, graph, tracker, entry_exit, action):
		ExternalFunction.__init__(self, signature, graph, tracker, entry_exit)
		self.action = action

		entry_size = self.tracker.get_observed_image(self.entry_id).top
		alpha, delta = self.action
		self.reads = to_stack_registers(range(entry_size - alpha, entry_size))
		self.reads.reverse()
		self.writes = \
			to_stack_registers(range(entry_size - alpha, entry_size - alpha + delta))
		self.writes.reverse()
		return

	def get_intcall_opcode(self):
		return INTERNAL_CALL_OPCODE + "%d" % self.signature

	def insert_intreturn(self):
		exit_block = self.graph[self.exit_id]
		new_block = exit_block.insert_intreturn()
		self.graph.replace_block(new_block)

	def __str__(self):
		prefix = "function_%x\n" % self.signature
		return prefix + ", ".join(self.reads) + "\n" + ", ".join(self.writes)

	def visualize_function(self):
		if not os.path.exists("temp/"):
			os.makedirs("temp/")
		self.graph.visualize("temp/temp.dot", (self.reads, self.writes))
		os.system("dot -Tpdf temp/temp.dot -o temp/0x%x.pdf" % self.signature)


class Structure:
	def __init__(self, block_id, suc_address, blocks):
		self.__block_id = block_id
		self.__exit_address = suc_address
		self.blocks = blocks

	def get_exit_address(self):
		return self.__exit_address

	def get_id(self):
		return self.__block_id

	def get_entry_address(self):
		return self.blocks[0].get_entry_address()

	def get_block(self, block_id):
		if self.__block_id == block_id:
			return self
		for block in self.blocks:
			result = block.get_block(block_id)
			if result is not None:
				return result

	def get_blocks(self):
		return self.blocks

	def get_nth_block(self, index):
		return self.blocks[index]


class Seq(Structure):
	def __init__(self, block_id, suc_address, blocks):
		Structure.__init__(self, block_id, suc_address, blocks)
		for b in blocks[:-1]:
			if isinstance(b, ExpressionBlock):
				b.remove_end_jump()

	def debug_block(self, depth):
		# print(prefix + "SEQ")
		for block in self.blocks:
			block.debug_block(depth)

	# print(prefix + "QES")

	def dot_format_block(self, depth):
		results = []
		for block in self.blocks:
			results.append(block.dot_format_block(depth))
		return "".join(results)

	def remove_end_jump(self):
		self.blocks[-1].remove_end_jump()


class IfThen(Structure):
	def __init__(self, block_id, suc_address, a0, a1):
		Structure.__init__(self, block_id, suc_address, [a0, a1])
		if isinstance(a1, ExpressionBlock):
			a1.remove_end_jump()

	def debug_block(self, depth):
		prefix = get_prefix(depth)
		print(prefix + "IF")
		self.blocks[0].debug_block(depth + 1)
		print(prefix + "THEN")
		self.blocks[1].debug_block(depth + 1)
		print(prefix + "FI")

	def dot_format_block(self, depth):
		prefix = get_prefix(depth)
		results = [
			self.blocks[0].dot_format_if_header(depth),
			self.blocks[1].dot_format_block(depth + 1),
			prefix + "}\l"]
		return "".join(results)


class IfThenElse(Structure):
	def __init__(self, block_id, suc_address, a0, a1, a2):
		Structure.__init__(self, block_id, suc_address, [a0, a1, a2])
		if isinstance(a1, ExpressionBlock):
			a1.remove_end_jump()
		if isinstance(a2, ExpressionBlock):
			a2.remove_end_jump()

	def debug_block(self, depth):
		prefix = get_prefix(depth)
		print(prefix + "IF")
		self.blocks[0].debug_block(depth + 1)
		print(prefix + "THEN")
		self.blocks[1].debug_block(depth + 1)
		print(prefix + "ELSE")
		self.blocks[2].debug_block(depth + 1)
		print(prefix + "FI")

	def dot_format_block(self, depth):
		prefix = get_prefix(depth)
		results = [
			self.blocks[0].dot_format_if_header(depth),
			self.blocks[1].dot_format_block(depth + 1),
			prefix + "} else {\l",
			self.blocks[2].dot_format_block(depth + 1),
			prefix + "}\l"]
		return "".join(results)


class Loop(Structure):
	def __init__(self, block_id, suc_address, a0, a1):
		Structure.__init__(self, block_id, suc_address, [a0, a1])
		# print(a1)
		if isinstance(a1, ExpressionBlock) or isinstance(a1, Seq):
			a1.remove_end_jump()

	def debug_block(self, depth):
		prefix = get_prefix(depth)
		print(prefix + "WHILE")
		self.blocks[0].debug_block(depth + 1)
		print(prefix + "DO")
		self.blocks[1].debug_block(depth + 1)
		print(prefix + "OD")

	def dot_format_block(self, depth):
		prefix = get_prefix(depth)
		results = [
			prefix + "while (0x1) {\l",
			self.blocks[0].dot_format_while_header(depth + 1),
			self.blocks[1].dot_format_block(depth + 1),
			prefix + "}\l",
		]
		return "".join(results)

