from ceptions import OperationError, PoisonException, ValidationError
from graphbuilder import FALLBACK_SIGNATURE
from instructions import *
from memorymodel import MemoryModel
from opcodes import *
from copy import deepcopy

WORD_MASK = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
INTRETURN_ADDRESS = -2


def execute_binop(inputs):
	opcode = inputs[0]
	arg_0, arg_1 = inputs[1], inputs[2]
	if opcode == "EXP":
		return (arg_0 ** arg_1) & WORD_MASK
	elif opcode == "SUB":
		return (arg_0 - arg_1) & WORD_MASK
	elif opcode == "AND":
		return (arg_0 & arg_1) & WORD_MASK
	elif opcode == "ADD":
		return (arg_0 + arg_1) & WORD_MASK
	elif opcode == "XOR":
		return (arg_0 ^ arg_1) & WORD_MASK
	elif opcode == "MUL":
		return (arg_0 * arg_1) & WORD_MASK
	elif opcode == "OR":
		return (arg_0 | arg_1) & WORD_MASK
	elif opcode == "LT":
		return arg_0 < arg_1
	elif opcode == "GT":
		return arg_0 > arg_1
	elif opcode == "DIV":
		return (arg_0 / arg_1) & WORD_MASK
	elif opcode == "EQ":
		return arg_0 == arg_1
	elif opcode == "MOD":
		return (arg_0 % arg_1) & WORD_MASK
	elif opcode == "BYTE":
		arg_1 = ("%x" % arg_1).zfill(64)
		# TODO: idk if this is right
		return int(arg_1[arg_0:arg_0 + 2], 16)
	elif opcode == "LEQ":
		return arg_0 <= arg_1
	elif opcode == "GEQ":
		return arg_0 >= arg_1
	elif opcode == "NEQ":
		return arg_0 != arg_1
	else:
		raise NotImplementedError("binop %s not implemented" % opcode)


def execute_fakeop(inputs):
	opcode = inputs[0]
	arg_0, arg_1 = inputs[1], inputs[2]
	if opcode == "LEQ":
		return arg_0 <= arg_1
	elif opcode == "GEQ":
		return arg_0 >= arg_1
	elif opcode == "NEQ":
		return arg_0 != arg_1
	elif opcode == "SR":
		return (arg_0 >> arg_1) & WORD_MASK
	elif opcode == "SL":
		return (arg_0 << arg_1) & WORD_MASK
	else:
		raise NotImplementedError("binop %s not implemented" % opcode)


def execute_monop(inputs):
	opcode = inputs[0]
	arg_0 = inputs[1]
	if opcode == "ISZERO":
		return (arg_0 == 0) & 1
	elif opcode == "NONZERO":
		return (arg_0 != 0) & 1
	elif opcode == "NOT":
		return (WORD_MASK - arg_0) & WORD_MASK
	raise NotImplementedError("monop %s not implemented" % opcode)


def int_to_word_hex(value):
	return ("%x" % value).zfill(64)


class BaseExecutor:
	def __init__(self, reader, lifter, debug):
		self.debug = debug
		self.reader = reader
		self.lifter = lifter

		self.__init_function_signature()
		self.__init_machine_state()
		self.__execute_contract()
		self.check_end_state()

	def __init_function_signature(self):
		self.signature = self.reader.signature

		if self.signature not in self.lifter.external_functions:
			self.signature = FALLBACK_SIGNATURE
	
		if self.debug:
			print(self.signature)

	def __init_machine_state(self):
		self.registers = dict()
		self.saved_states = list()

		func = self.lifter.external_functions[self.signature]
		self.reader.fast_forward_trace(func.get_begin_address())
		state = self.reader.get_cur_state()
		for index, value in enumerate(state['stack']):
			register = STACK_REGISTER + str(index)
			self.registers[register] = int(value, 16)
		chunk = "".join([i.encode("utf-8") for i in state['memory']])
		self.memory = MemoryModel(chunk)
		self.registers["$m"] = self.memory.load_as_int(64)

	def __execute_contract(self):
		func = self.lifter.external_functions[self.signature]
		try:
			self.execute_function(func)
		except PoisonException:
			pass  # this is fine, just do final check

	def execute_function(self, func):
		cur_id = func.entry_id
		count = 0
		while cur_id is not None:
			address = self.execute_block(func.graph[cur_id])

			if address == INTRETURN_ADDRESS:
				return  # return from recursive call

			if address is None:
				cur_id = func.graph.get_natural_successor(cur_id)
			else:
				cur_id = self.get_jump_successor(func.graph, cur_id, address)
			count += 1

	def execute_block(self, block):
		if self.debug:
			print("block_%d" % block.get_id())
			# self.debug_register()

		# self.memory.debug_memory()
		# cur_block = func.graph[cur_id]
		address = None
		for item in block:
			if self. debug:
				self.debug_register()
				print(str(item.address) + "\t" + str(item).lower())
				# print(inputs)

				pass
			address = self.execute_item(item)
		return address

	def execute_item(self, item):
		inputs = self.load_inputs(item, 0)
		opcode = item.opcode
		output = self.execute_opcode(opcode, inputs)
		# if item.opcode == "SR":
		# 	print(output)
		self.store_output(item, output)

		if "INTCALL" in opcode:
			self.issue_intcall(item, inputs)
		elif opcode == "INTRET":
			return INTRETURN_ADDRESS   # recursive call returns

		if opcode == "JUMP" or \
			(opcode == "JUMPI" and inputs[2] != 0):
			return inputs[1]
		if opcode == "ASSERT" and inputs[1] == 0:
				raise PoisonException("assert")
		if opcode in exit_ops:
			raise PoisonException("exit")

	def load_inputs(self, item, depth=0):
		raise NotImplementedError("must be overridden")

	def execute_opcode(self, opcode, inputs):
		output = None
		if opcode in free_ops:
			output = self.__execute_free_ops(opcode, inputs)
		elif opcode in fake_ops:
			output = execute_fakeop(inputs)
		elif opcode == "MOVE":
			output = inputs[1]
		elif opcode == "SSTORE":
			self.reader.do_sstore(inputs)
		elif opcode == "SLOAD":
			output = self.reader.do_sload(inputs)
		elif opcode in effect_ops:
			output = self.__execute_effect_ops(opcode, inputs)
		elif opcode == "SHA3R":
			self.__execute_sha3r(opcode, inputs)
		# effect_ops happens to be a subset of mem_write_ops
		# so this will handle the rest (whatever)
		elif opcode in mem_read_ops | mem_write_ops:
			output = self.__execute_mem_ops(opcode, inputs)
		return output

	def __execute_free_ops(self, opcode, inputs):
		if self.reader.free_ops.in_mapping(inputs):
			return self.reader.free_ops.lookup_mapping(inputs)
		else:
			if opcode in bin_ops:
				return execute_binop(inputs)
			elif opcode in mono_ops:
				return execute_monop(inputs)
			else:
				if self.reader.do_end_check() and self.reader.error:
					raise PoisonException("free op not found")
				print(inputs)
				raise OperationError("free op " + opcode)

	def __execute_effect_ops(self, opcode, inputs):
		if opcode in call_ops:
			in_offset, in_size = inputs[-4], inputs[-3]
			out_offset, out_size = inputs[-2], inputs[-1]
			chunk = self.memory.load_as_str(in_offset, in_size)
			if opcode == "DELEGATECALL":
				inputs = (opcode, inputs[1], chunk, out_offset, out_size)
			else:
				inputs = (opcode, inputs[1], inputs[2], chunk, out_offset, out_size)
			# print(inputs)
			output = self.reader.do_effect_ops(inputs)
			self.memory.store(out_offset, out_size, output[1])
			return output[0]
		elif opcode in log_ops | {"RETURN"}:
			offset, size = inputs[1], inputs[2]
			chunk = self.memory.load_as_str(offset, size)
			inputs = tuple([opcode, chunk] + list(inputs[3:]))
			return self.reader.do_effect_ops(inputs)
		elif opcode == "CREATE":
			offset, size = inputs[2], inputs[3]
			chunk = self.memory.load_as_str(offset, size)
			inputs = (opcode, chunk)
			return self.reader.do_effect_ops(inputs)
		else:
			raise NotImplementedError("effect op " + opcode + "not executed")

	def __execute_mem_ops(self, opcode, inputs):
		if opcode == "MLOAD":
			value = self.memory.load_as_int(inputs[1])
			return value
		elif opcode == "MSTORE":
			value = int_to_word_hex(inputs[2])
			self.memory.store(inputs[1], 32, value)
		elif opcode == "SHA3":
			offset, size = inputs[1], inputs[2]
			chunk = self.memory.load_as_str(offset, size)
			inputs = (opcode, chunk)
			return self.reader.do_mem_ops(inputs)
		elif opcode in {"CODECOPY", "CALLDATACOPY"}:
			chunk = self.reader.do_mem_ops(inputs)
			self.memory.store(inputs[1], inputs[3], chunk)
		elif opcode == "EXTCODECOPY":
			chunk = self.reader.do_mem_ops(inputs)
			self.memory.store(inputs[2], inputs[4], chunk)
		elif opcode == "MSTORE8":
			value = int_to_word_hex(inputs[2])
			value = value[-2:]
			self.memory.store(inputs[1], 1, value)
		else:
			print(inputs)
			assert False

	def __execute_sha3r(self, opcode, inputs):
		if opcode == "SHA3r":
			chunk = "".join([int_to_word_hex(i) for i in inputs[1:]])
			self.memory.store(0, len(chunk) / 2, chunk)
			inputs = ("SHA3", chunk)
			return self.reader.do_mem_ops(inputs)

	def store_output(self, item, output):
		if output is None:
			return
		write = item.writes[0]
		self.registers[write] = output

	def get_jump_successor(self, graph, cur_id, address):
		for suc_id in graph.get_successor_ids(cur_id):
			if graph[suc_id].get_entry_address() == address:
				return suc_id
		raise PoisonException("exit")

	def check_end_state(self):
		if not self.reader.do_end_check():
			raise ValidationError("outstanding operations")

	def debug_register(self):
		print("-" * 32)
		registers = set(self.registers.keys()) - {"$t", "$m"}
		registers = sorted(registers, key=lambda x: int(x[2:]))
		for r in registers:
			value = ("%x" % self.registers[r])
			print(r + ":\t" + value)
		# if "$t" in self.registers:
		for r in {"$t", "$m"}:
			if r not in self.registers:
				continue
			value = ("%x" % self.registers[r])
			print(r + ":\t" + value)
		print("-" * 32)

	def issue_intcall(self, instruction, inputs):
		opcode = instruction.opcode
		# get the invoked function
		signature = int(opcode[7:])
		func = self.lifter.internal_functions[signature]
		# save the register state
		saved = deepcopy(self.registers)
		self.saved_states.append(saved)

		self.registers = dict()
		# assert len(instruction.reads) == len(func.reads)
		for index in range(len(instruction.reads)):
			dst_register = func.reads[index]
			self.registers[dst_register] = inputs[index + 1]

		self.registers["$m"] = saved["$m"]
		self.execute_function(func)

		saved = self.saved_states.pop()
		# assert len(instruction.writes) == len(func.writes)
		for index in range(len(instruction.writes)):
			src_register = instruction.writes[index]
			dst_register = func.writes[index]
			saved[src_register] = self.registers[dst_register]
		saved["$m"] = self.registers["$m"]
		self.registers = saved
