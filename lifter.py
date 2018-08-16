from opcodes import *
from bytecodes import *
from instructions import *

from graphbuilder import GraphBuilder
from interpreter import BasicInterpreter
from interpreter import DuplicateInterpreter
from structures import InternalFunction
from ceptions import StackSizeError
from instructionblock import InstructionBlock

from collections import defaultdict
import sys


class Lifter(GraphBuilder):
	def __init__(self, binary):
		GraphBuilder.__init__(self, binary)
		# for func in self.external_functions.values():
		# 	func.visualize_function()

		self.__label_function_boundaries()
		self.__create_internal_functions()

		self.__reduce_functions()

		for func in self.get_all_functions():
			self.__lift_function(func)
		# self.__split_hub_blocks(func)

	def __label_function_boundaries(self):
		# TODO: extend to include undetected callers ?
		# maps callee_pair (callee_entry, callee_exit) to caller_pairs
		self.__callee_pairs = dict()
		for callee_exit, caller_begins in self.indirect_jumps.items():
			for caller_begin, caller_end in caller_begins.items():
				# caller_begin should not be jumpi
				if self.graph[caller_begin].is_jumpi_block():
					# print(caller_begin)
					continue

				suc_ids = self.graph.get_successor_ids(caller_begin)
				if len(suc_ids) == 1:
					callee_pair = (suc_ids.pop(), callee_exit)
					if callee_pair not in self.__callee_pairs:
						self.__callee_pairs[callee_pair] = set()
					self.__callee_pairs[callee_pair].add((caller_begin, caller_end))
				else:
					print("[WARNING] caller successor not unique %s" % caller_begin)

	def __create_internal_functions(self):
		self.internal_functions = dict()
		for callee_pair, caller_pairs in self.__callee_pairs.items():
			# print(caller_pairs)
			func, caller_pairs = self.__create_internal_function(callee_pair, caller_pairs)
			if len(caller_pairs) <= 1:
				del (self.__callee_pairs[callee_pair])
			else:
				self.__callee_pairs[callee_pair] = caller_pairs
				# print(caller_pairs)
				self.internal_functions[callee_pair] = func
				opcode = func.get_intcall_opcode()
				func.insert_intreturn()
				actions[opcode] = func.action

	def __create_internal_function(self, callee_pair, caller_pairs):
		possible_funcs = dict()
		callee_begin, callee_end = callee_pair

		for caller_pair in caller_pairs:
			caller_begin, caller_end = caller_pair

			caller_begin_image = self.tracker.get_observed_image(callee_begin, caller_begin)
			interpreter = BasicInterpreter(self.graph.get_blocks(), self.resolver)
			interpreter.add_to_poison(caller_end)

			sub_graph, sub_tracker = \
				interpreter.explore_control_flow_graph(callee_begin, caller_begin_image)
			sub_graph.remove_block(caller_end)  # this might not be safe

			end_path = interpreter.get_end_path()
			operations = interpreter.compute_stack_actions(end_path)
			# print(delta, alpha)
			signature = len(self.internal_functions)
			in_func = \
				InternalFunction(signature, sub_graph, sub_tracker, callee_pair, operations)

			block_ids = frozenset(sub_graph.get_block_ids())
			if block_ids not in possible_funcs:
				possible_funcs[block_ids] = [set(), in_func]
			possible_funcs[block_ids][0].add(caller_pair)

		caller_pairs, func = max(possible_funcs.values(), key=lambda x: len(x[0]))

		return func, caller_pairs

	def __reduce_functions(self):
		for func in self.get_all_functions():
			self.__extract_internal_calls(func)
			entry_id = func.entry_id
			entry_image = func.tracker.get_observed_image(entry_id)

			interpreter = DuplicateInterpreter(
				func.graph.get_blocks(), self.resolver.get_natural_successors())
			func.resolver = interpreter.resolver

			interpreter.add_to_poison(func.exit_id)
			new_graph, new_tracker = \
				interpreter.explore_control_flow_graph(entry_id, entry_image)
			func.graph, func.tracker = new_graph, new_tracker
			func.ins_outs = interpreter.ins_outs

		for callee_pair in self.internal_functions.keys():
			func = self.internal_functions.pop(callee_pair)
			self.internal_functions[func.signature] = func

	def __extract_internal_calls(self, func):
		callee_pairs = self.__get_present_pairs(func)
		# print(callee_pairs)
		for callee_pair, caller_pairs in callee_pairs.items():
			in_func = self.internal_functions[callee_pair]
			opcode = in_func.get_intcall_opcode()
			for caller_pair in caller_pairs:
				func.extract_intcall(callee_pair, caller_pair, opcode)

	def __get_present_pairs(self, func):
		graph = func.graph
		callee_pairs = dict()
		for callee_pair, caller_pairs in self.__callee_pairs.items():
			if not graph.has_blocks(callee_pair):
				continue
			present_caller_pairs = set()
			for caller_pair in caller_pairs:
				if not graph.has_blocks(caller_pair):
					continue

				present_caller_pairs.add(caller_pair)
			if len(present_caller_pairs) != 0:
				callee_pairs[callee_pair] = present_caller_pairs

		caller_begins = defaultdict(int)

		# remove the case in which one caller has multiple callees
		for callee_pair, caller_pairs in callee_pairs.items():
			for caller_pair in caller_pairs:
				caller_begin, _ = caller_pair
				caller_begins[caller_begin] += 1
				if caller_begins[caller_begin] > 1:
					del (callee_pairs[callee_pair])
					break

		return callee_pairs

	def __lift_function(self, func):

		for block in func.graph:
			str_id = block.get_id()
			stack_size = set()
			for image in func.tracker.get_observed_images(str_id):
				stack_size.add(image.top)
			if len(stack_size) != 1:
				raise StackSizeError("lifter stack size error")

			stack_size = stack_size.pop()
			block = self.__lift_bytecode_block(block, stack_size)
			func.graph.replace_block(block)

	def __lift_bytecode_block(self, block, stack_size):
		entry_addr = block.get_entry_address()
		new_block = InstructionBlock(block.get_id(), entry_addr)
		for bytecode in block:
			instructions, stack_size = \
				self.__lift_bytecode(bytecode, stack_size)
			for instruction in instructions:
				new_block.append(instruction)
		new_block.exit_stack_size = stack_size
		# print(new_block.exit_stack_size)
		return new_block

	@staticmethod
	def __lift_bytecode(bytecode, stack_size):
		opcode = bytecode.opcode
		address = bytecode.get_address()
		delta, alpha = actions[opcode][:2]

		reads = to_stack_registers([stack_size - i - 1 for i in range(delta)])
		writes = to_stack_registers([stack_size - delta + i for i in range(alpha)])
		instructions = list()

		if opcode in swap_ops:
			read1 = [STACK_REGISTER + str(stack_size - delta)]
			read2 = [STACK_REGISTER + str(stack_size - 1)]
			instructions = [MoveInstruction("MOVE", read1, [SWAP_REGISTER], address),
			                MoveInstruction("MOVE", read2, read1, address),
			                MoveInstruction("MOVE", [SWAP_REGISTER], read2, address)]
		elif opcode in dup_ops:
			reads = [STACK_REGISTER + str(stack_size - delta)]
			writes = [STACK_REGISTER + str(stack_size)]
			instructions = [MoveInstruction("MOVE", reads, writes, address)]
		elif opcode in push_ops:
			constant = bytecode.dependencies[0]
			instructions = [MoveInstruction("MOVE", [constant], writes, address)]
		elif opcode in bin_ops:
			instructions = [BinOpInstruction(opcode, reads, writes, address)]
		elif opcode in mono_ops:
			instructions = [MonoOpInstruction(opcode, reads, writes, address)]
		elif opcode == "MSTORE":
			instructions = [MstoreInstruction(opcode, reads, writes, address)]
		elif opcode == "MLOAD":
			instructions = [MloadInstruction(opcode, reads, writes, address)]
		elif opcode == "CALLDATALOAD":
			instructions = [CallLoadInstruction(opcode, reads, writes, address)]
		elif opcode.startswith("INTCALL"):
			instructions = [IntCallInstruction(opcode, reads, writes, address)]
		elif opcode == "SSTORE":
			instructions = [SstoreInstruction(opcode, reads, writes, address)]
		elif opcode == "SLOAD":
			instructions = [SloadInstruction(opcode, reads, writes, address)]
		elif opcode not in {"POP", "JUMPDEST"}:
			instructions = [Instruction(opcode, reads, writes, address)]
		stack_size = stack_size - delta + alpha  # update stack size
		return instructions, stack_size

	def get_all_functions(self):
		return list(self.external_functions.values()) + \
		       list(self.internal_functions.values())

	def debug_callee_pairs(self):
		for callee_pair, caller_pairs in self.__callee_pairs.items():
			print(callee_pair)
			print(list(caller_pairs))
			print("")

	def debug_functions(self):
		for func in self.get_all_functions():
			func.debug_function()
		# func.visualize_function()

	@staticmethod
	def __split_hub_blocks(func):
		graph = func.graph
		resolver = func.resolver

		for block_id in graph.get_block_ids():
			block = graph[block_id]
			if not block.check_exit_instruction("JUMP"):
				continue
			successor_ids = graph.get_successor_ids(block_id)
			if len(successor_ids) <= 1:
				continue
			if block_id not in func.ins_outs:
				continue

			for pre_id, suc_id in func.ins_outs[block_id].items():
				if len(suc_id) == 1:
					suc_id = suc_id.pop()
					new_id = resolver.allocate_id()
					new_block = block.make_copy(new_id)
					graph.add_block(new_block)
					# new_block.debug_block()
					# block.debug_block()

					graph.remove_edge(pre_id, block_id)
					graph.remove_edge(block_id, suc_id)

					graph.add_edge(pre_id, new_id)
					graph.add_edge(new_id, suc_id)

		merged = graph.simplify({})
		exit_id = func.exit_id
		while exit_id in merged:
			exit_id = merged[exit_id]
		func.exit_id = exit_id


if __name__ == "__main__":
	input_file = open(sys.argv[1])
	line = input_file.readline().strip()
	if " " in line:
		line = line.split(" ")[1]
	input_file.close()
	a = Lifter(line)

	if "-v" in sys.argv:
		a.visualize_contract()
	if "-d" in sys.argv:
		a.debug_functions()
