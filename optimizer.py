from structures import InternalFunction
from lifter import Lifter
from blockstate import ConstantState
from blockstate import CopyState
from blockstate import MemState


from opcodes import *
from baseexecutor import execute_binop, execute_monop
from instructions import MoveInstruction, Instruction

import sys, math


def apply_peephole_optimizations(func):
	for block in func.graph:
		__order_operands(block)
		__size_one_rewrites(block)
		__size_two_rewrites(block)
		rewrite_free_ptr(block)
		# __sha3_rewrites(block)


def __order_operands(block):
	for instruction in block:
		if instruction.opcode not in {"AND", "ADD", "MUL", "OR", "EQ", "XOR"}:
			continue
		reads = instruction.reads
		if isinstance(reads[0], str) != isinstance(reads[1], str):
			if isinstance(reads[0], str):
				instruction.reads.reverse()


def __size_one_rewrites(block):
	instructions = block.get_instructions()
	for i, instruction in enumerate(instructions):
		__remove_self_assign(i, instruction, block)
		__fold_constant(i, instruction, block)
		__rewrite_word_add(instruction)
		__rewrite_shift(i, instruction, block)
		__rewrite_move(i, instruction, block)
		# __rewrite_assert(i, instruction, block)


def __remove_self_assign(i, instruction, block):
	if instruction.opcode == "MOVE" and \
			(instruction.reads[0] == instruction.writes[0]):
		block.set_nop_instruction(i)
	if instruction.opcode == "AND" and instruction.reads[1] == WORD_MASK and \
			(instruction.reads[0] == instruction.writes[1]):
		block.set_nop_instruction(i)


def __fold_constant(i, instruction, block):
	opcode = instruction.opcode
	constants = instruction.get_constants()
	if not constants:
		return
	inputs = [opcode] + constants
	writes = instruction.writes
	address = instruction.address
	if opcode in bin_ops:
		try:
			value = execute_binop(inputs)
		except ZeroDivisionError:
			return
		new_instruction = MoveInstruction("MOVE", [value], writes, address)
		block.set_instruction(i, new_instruction)
	elif opcode in mono_ops:
		value = execute_monop(inputs)
		new_instruction = MoveInstruction("MOVE", [value], writes, address)
		block.set_instruction(i, new_instruction)


def __rewrite_word_add(instruction):
	if instruction.opcode != "ADD":
		return
	if instruction.reads[0] != WORD_MASK:
		return
	instruction.opcode = "SUB"
	instruction.reads[0] = instruction.reads[1]
	instruction.reads[1] = 1


def __rewrite_shift(i, instruction, block):
	opcode = instruction.opcode
	address = instruction.address
	if opcode not in {"DIV", "MUL"}:
		return
	if opcode == "DIV":
		num = instruction.reads[1]
		if isinstance(num, str):
			return
		if not (((num & (num - 1)) == 0) and num > 256):
			return
		exp = int(math.log(num, 2))
		new_instruction = \
			Instruction("SR", [instruction.reads[0], exp], instruction.writes, address)
		block.set_instruction(i, new_instruction)
	elif opcode == "MUL":
		num = instruction.reads[0]
		if isinstance(num, str):
			return
		if not (((num & (num - 1)) == 0) and num > 256):
			return
		exp = int(math.log(num, 2))
		new_instruction = \
			Instruction("SL", [instruction.reads[1], exp], instruction.writes, address)
		block.set_instruction(i, new_instruction)


def __rewrite_move(i, instruction, block):
	opcode = instruction.opcode
	reads = instruction.reads
	writes = instruction.writes
	address = instruction.address
	if opcode == "DIV" and reads[1] == 1:
		new_instruction = MoveInstruction("MOVE", [reads[0]], writes, address)
		block.set_instruction(i, new_instruction)
	elif opcode == "ADD" and reads[0] == 0:
		new_instruction = MoveInstruction("MOVE", [reads[1]], writes, address)
		block.set_instruction(i, new_instruction)
	elif opcode == "MUL" and reads[0] == 1:
		new_instruction = MoveInstruction("MOVE", [reads[1]], writes, address)
		block.set_instruction(i, new_instruction)
	elif opcode == "AND" and reads[0] == WORD_MASK:
		new_instruction = MoveInstruction("MOVE", [reads[1]], writes, address)
		block.set_instruction(i, new_instruction)
	elif opcode == "SUB" and reads[0] == reads[1]:
		new_instruction = MoveInstruction("MOVE", [0], writes, address)
		block.set_instruction(i, new_instruction)


# def __rewrite_assert(i, instruction, block):
# 	reads = instruction.reads
# 	if instruction.opcode == "JUMPI" and reads[0] == 0:
# 		new_instruction = Instruction("ASSERT", [reads[1]], [], instruction.address)
# 		block.set_instruction(i, new_instruction)


def __size_two_rewrites(block):
	instructions = block.get_instructions()
	for i in range(1, len(instructions)):
		ins_0, ins_1 = instructions[i - 1:i + 1]
		__remove_double_mask(i, ins_0, ins_1, block)
		__remove_address_mask(i, ins_0, ins_1, block)
		__remove_doube_iszero(i, ins_0, ins_1, block)
	# want to remove double iszero first
	for i in range(1, len(instructions)):
		ins_0, ins_1 = instructions[i - 1:i + 1]
		__rewrite_negate_ops(i, ins_0, ins_1, block)


def __remove_double_mask(i, instruction_0, instruction_1, block):
	if instruction_0.opcode != "AND" or \
		instruction_1.opcode != "AND":
		return
	w_0 = instruction_0.writes[0]
	w_1 = instruction_1.writes[0]
	reads_0 = instruction_0.reads
	reads_1 = instruction_1.reads

	if reads_0[0] != reads_1[0] or \
		w_0 != reads_1[1] or \
		w_0 != w_1:
		return
	block.set_nop_instruction(i - 1)
	instruction_1.reads[1] = reads_0[1]


def __remove_address_mask(i, instruction_0, instruction_1, block):
	if instruction_0.opcode not in {"CALLER", "ADDRESS"} or \
		instruction_1.opcode != "AND":
		return
	w_0 = instruction_0.writes[0]
	w_1 = instruction_1.writes[0]
	reads_1 = instruction_1.reads
	if reads_1[0] != ADDRESS_MASK or reads_1[1] != w_0:
		return
	address = instruction_1.address
	instruction_1 = MoveInstruction("MOVE", [w_0], [w_1], address)
	block.set_instruction(i, instruction_1)


def __remove_doube_iszero(i, instruction_0, instruction_1, block):
	if instruction_0.opcode != "ISZERO" or \
		instruction_1.opcode != "ISZERO" or \
		instruction_1.address != instruction_0.address + 1:
		return
	block.set_nop_instruction(i - 1)
	block.set_nop_instruction(i)


def __rewrite_negate_ops(i, instruction_0, instruction_1, block):
	opcode = instruction_0.opcode
	if instruction_0.opcode not in negate_ops or \
		instruction_1.opcode != "ISZERO" or \
		instruction_1.address != instruction_0.address + 1:
		return
	block.set_nop_instruction(i - 1)
	opcode = negate_ops[opcode]
	new_instruction = \
		Instruction(opcode, instruction_0.reads, instruction_0.writes, instruction_0.address)
	block.set_instruction(i, new_instruction)


def __sha3_rewrites(block):
	local_memory = MemState()
	instructions = block.get_instructions()
	for index, instruction in enumerate(instructions):
		if instruction.opcode == "SHA3":
			begin, end = instruction.reads
			if begin == 0 and not isinstance(end, str):
				addresses = range(begin, end, 32)
				items = local_memory.lookup_mapping(addresses)
				if len(items) != 0:
					values, indices = zip(*items)
					for i in indices:
						block.set_nop_instruction(i)
					operation = Instruction("SHA3R", list(values), instruction.writes, instruction.address)
					block.set_instruction(index, operation)
		local_memory.add_mapping(index, instruction)


def rewrite_free_ptr(block):
	for i, instruction in enumerate(block.get_instructions()):
		opcode = instruction.opcode
		if opcode == "MLOAD" and \
			instruction.reads[0] == 64:
			new_instruction = MoveInstruction("MOVE", ["$m"], instruction.writes, instruction.address)
			block.set_instruction(i, new_instruction)
		elif opcode == "MSTORE" and \
			instruction.reads[0] == 64:
			new_instruction = MoveInstruction("MOVE", [instruction.reads[1]], ["$m"], instruction.address)
			block.set_instruction(i, new_instruction)


def push_down_definition(block):
	instructions = block.get_instructions()
	for i, instruction in enumerate(instructions):
		writes = instruction.writes
		if len(writes) != 1:
			continue
		ui = get_single_use(i, instruction, instructions)
		if ui == -1:
			continue
		if can_reach(instruction, i, ui, instructions):
			block.set_nop_instruction(i)
			instruction.writes[0] = instructions[ui].writes[0]
			block.set_instruction(ui, instruction)


def get_single_use(begin, d, instructions):
	wr = d.writes[0]
	ui, count = -1, 0
	killed = False
	for i, u in enumerate(instructions):
		if i < begin + 1:
			continue
		if u.reads_from(wr):
			ui = i
			count += 1
		if u.writes_to(wr):
			killed = True
			break
	u = instructions[ui]
	if count == 1 and killed and u.opcode == "MOVE":
		return ui
	return -1


def can_reach(d, begin, end, instructions):
	mload = d.opcode == "MLOAD"
	if d.opcode in mem_read_ops | {"SLOAD"} and not mload:
		return False

	targets = set(d.writes + d.reads)
	# print(instructions[begin])
	for u in instructions[begin + 1:end]:
		if mload and u.opcode in mem_write_ops:
			return False
		for r in u.writes:
			if r in targets:
				return False
	return True


class Optimizer(Lifter):
	def __init__(self, binary):
		Lifter.__init__(self, binary)
		# return
		self.__debug = False

		for func in self.get_all_functions():
			self.__optimize_function(func)

	def __optimize_function(self, func):
		self.change = True
		while self.change:
			self.change = False
			self.__propagate_constant_values(func)
			self.__propagate_copy_instructions(func)
			apply_peephole_optimizations(func)
			for block in func.graph:
				push_down_definition(block)
			self.__eliminate_dead_instructions(func)

	def __propagate_constant_values(self, func):
		self.__outs = dict()
		self.__compute_constant_states(func)
		self.__apply_constant_propagation(func)

	def __compute_constant_states(self, func):
		graph = func.graph
		for block in graph:
			block_id = block.get_id()
			self.__outs[block_id] = ConstantState()

		change = True
		while change:
			change = False
			for block in graph:
				block_id = block.get_id()
				new_out = ConstantState()

				for pre in graph.get_predecessor_ids(block_id):
					new_out.join(self.__outs[pre])

				for inst in block:
					new_out.add_mapping(inst)

				if not (self.__outs[block_id] == new_out):
					self.__outs[block_id] = new_out
					change = True

	def __apply_constant_propagation(self, func):
		graph = func.graph
		for block in graph:
			block_id = block.get_id()

			before = ConstantState()
			for pre in graph.get_predecessor_ids(block_id):
				before.join(self.__outs[pre])

			for instruction in block:
				before.apply_mapping(instruction)
				before.add_mapping(instruction)

	def get_liveness_states(self, func):
		self.__outs = dict()
		self._uses, self._defs = dict(), dict()
		self.__compute_liveness_states(func)
		if isinstance(func, InternalFunction):  # must keep all return registers alive
			assert func.exit_id != -1
			self.__outs[func.exit_id] |= set(func.writes)
		return self.__outs

	def __eliminate_dead_instructions(self, func):
		self.__outs = dict()
		self._uses, self._defs = dict(), dict()
		self.__compute_liveness_states(func)
		if isinstance(func, InternalFunction):  # must keep all return registers alive
			assert func.exit_id != -1
			self.__outs[func.exit_id] |= set(func.writes)
		self.__apply_instruction_elimination(func)

	def __compute_liveness_states(self, func):
		graph = func.graph
		for block in graph:
			block_id = block.get_id()
			self.__compute_use_def(block)
			self.__outs[block_id] = set()

		change = True
		while change:
			change = False
			for block in graph:
				block_id = block.get_id()
				# anything
				new_out = set()
				for suc in graph.get_successor_ids(block_id):
					u, d = self._uses[suc], self._defs[suc]
					# u is used in suc without definition
					# d is defined in suc, kills out[suc]
					new_out |= (u | (self.__outs[suc] - d))
				if self.__outs[block_id] != new_out:
					self.__outs[block_id] = new_out
					change = True
		for out in self.__outs.values():
			out.add("$m")

	def __compute_use_def(self, block):
		block_id = block.get_id()
		d, u = set(), set()
		for instruction in block:
			for read in instruction.get_read_registers():
				if read not in d:
					u.add(read)
			for write in instruction.writes:
				d.add(write)
		self._defs[block_id] = d
		self._uses[block_id] = u

	def __apply_instruction_elimination(self, func):
		# change = False
		graph = func.graph
		for block in graph:
			block_id = block.get_id()
			out = self.__outs[block_id]

			new_instructions = list()
			for instruction in reversed(block.get_instructions()):
				reads = instruction.get_read_registers()
				writes = instruction.get_write_registers()
				opcode = instruction.opcode

				if opcode in throw_away_ops and len(writes & out) == 0:
					self.change = True
					continue  # do not include
				else:
					out = (out - writes) | reads
					new_instructions.append(instruction)

			new_instructions.reverse()
			block.set_instructions(new_instructions)

	def __propagate_copy_instructions(self, func):
		self.__outs = dict()
		self.__compute_copy_states(func)
		self.__apply_copy_propagation(func)

	def __compute_copy_states(self, func):
		graph = func.graph
		for block in graph:
			block_id = block.get_id()
			self.__outs[block_id] = CopyState()

		change = True
		while change:
			change = False
			for block in graph:
				block_id = block.get_id()
				new_out = CopyState()

				for pre in graph.get_predecessor_ids(block_id):
					new_out.join(self.__outs[pre])

				for instruction in block:
					new_out.add_mapping(instruction)

				if not (self.__outs[block_id] == new_out):
					self.__outs[block_id] = new_out
					change = True

	def __apply_copy_propagation(self, func):
		graph = func.graph
		for block in graph:
			block_id = block.get_id()
			before = CopyState()

			for pre in graph.get_predecessor_ids(block_id):
				before.join(self.__outs[pre])

			# print(before.mapping)
			for instruction in block:
				before.apply_mapping(instruction)
				before.add_mapping(instruction)
		# self.__outs[block_id] = CopyState()


if __name__ == "__main__":
	input_file = open(sys.argv[1])
	line = input_file.readline().strip()
	if " " in line:
		line = line.split(" ")[1]
	input_file.close()
	a = Optimizer(line)
	if "-d" in sys.argv:
		a.debug_functions()
