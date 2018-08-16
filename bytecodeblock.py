from ceptions import InternalFunctionError
from bytecodes import *
from opcodes import INTERNAL_RETURN_OPCODE, exit_ops

import array, hashlib
import operator
from copy import deepcopy


class BytecodeBlock(object):
	def __init__(self, block_id):
		self.__block_id = block_id
		self.__items = list()

	def append(self, item):
		item.set_container_block_id(self.get_id())
		self.__items.append(item)

	def remove(self, index):
		del(self.__items[index])

	def insert(self, item, index):
		self.__items.insert(index, item)

	def get_id(self):
		return self.__block_id

	def get_block_size(self):
		return len(self.__items)

	def get_items(self):
		return self.__items

	def get_entry_address(self):
		return self.__items[0].get_address()

	def get_entry_bytecode(self):
		return self.__items[0]

	def get_exit_bytecode(self):
		return self.__items[-1]

	def is_exit_block(self):
		exit_bytecode = self.get_exit_bytecode()
		return exit_bytecode.opcode in exit_ops

	def is_jumpi_block(self):
		exit_bytecode = self.get_exit_bytecode()
		return exit_bytecode.opcode == "JUMPI"

	def is_jump_block(self):
		exit_bytecode = self.get_exit_bytecode()
		return exit_bytecode.opcode == "JUMP"

	def get_jumpi_address(self):
		if len(self.__items) < 2:
			return None
		jumpi_bytecode = self.__items[-1]
		push_bytecode = self.__items[-2]
		if jumpi_bytecode.opcode == "JUMPI" \
			and isinstance(push_bytecode, PushByteCode):
			return push_bytecode.get_value()

	def is_abort_block(self):
		exit_bytecode = self.__items[-1]
		if exit_bytecode.opcode in {"REVERT", "INVALID"}:
			return True
		if len(self.__items) < 2:
			return False
		push_bytecode = self.__items[-2]

		return exit_bytecode.opcode == "JUMP" \
			and isinstance(push_bytecode, PushByteCode)\
			and push_bytecode.get_value() in {2, 0}

	def get_function_signature(self):
		bytecodes = self.__items
		if len(self.__items) < 5: return -1
		bytecode_1 = bytecodes[-5]
		bytecode_2 = bytecodes[-4]
		bytecode_3 = bytecodes[-3]
		bytecode_4 = bytecodes[-2]
		bytecode_5 = bytecodes[-1]
		if bytecode_1.opcode == "DUP1" \
			and bytecode_2.opcode in {"PUSH4", "PUSH3"} \
			and bytecode_3.opcode == "EQ" \
			and isinstance(bytecode_4, PushByteCode) \
			and bytecode_5.opcode == "JUMPI":
			return bytecode_2.get_value()
		if bytecode_1.opcode in {"PUSH4", "PUSH3"} \
			and bytecode_2.opcode == "DUP2" \
			and bytecode_3.opcode == "EQ" \
			and isinstance(bytecode_4, PushByteCode) \
			and bytecode_5.opcode == "JUMPI":
			return bytecode_1.get_value()

		if len(self.__items) < 6: return -1
		bytecode_0 = bytecodes[-6]

		if bytecode_0.opcode == "DUP1" \
			and bytecode_1.opcode in {"PUSH4", "PUSH3"} \
			and bytecode_2.opcode == "EQ" \
			and bytecode_3.opcode == "ASSERT":
			return bytecode_1.get_value()
		if bytecode_0.opcode in {"PUSH4", "PUSH3"} \
			and bytecode_1.opcode == "DUP2" \
			and bytecode_2.opcode == "EQ" \
			and bytecode_3.opcode == "ASSERT":
			return bytecode_0.get_value()

		return -1

	def insert_assert(self):
		jumpi_bytecode = self.__items[-1]
		assert_bytecode = ByteCode("ASSERT", "", jumpi_bytecode.get_address(), -1)
		self.insert(assert_bytecode, -2)
		jumpi_bytecode.opcode = "JUMP"

	def insert_intcall(self, opcode, caller_end):
		new_block = self.make_copy()
		bytecodes = new_block.get_items()

		exit_bytecode = bytecodes[-1]
		if exit_bytecode.opcode == "JUMP":
			exit_bytecode.opcode = "POP"
		else:
			assert exit_bytecode.opcode != "JUMPI"
		intcall_bytecode = ByteCode(opcode, "gg", exit_bytecode.get_address(), 1)
		new_block.append(intcall_bytecode)
		push_bytecode = PushByteCode("PUSH1", "", exit_bytecode.get_address(), 2)
		address = caller_end.get_entry_address()
		push_bytecode.set_dependency(0, address)

		new_block.append(push_bytecode)
		jump_bytecode = ByteCode("JUMP", "", exit_bytecode.get_address(), 3)
		new_block.append(jump_bytecode)
		new_block.__block_id = self.get_id()
		# new_block.debug_block()

		return new_block

	def insert_intreturn(self):
		new_block = self.make_copy()
		bytecodes = new_block.get_items()
		bytecode_0 = bytecodes[-1]
		assert bytecode_0.opcode == "JUMP"

		new_block.__items[-1] = ByteCode("POP", "gg", bytecode_0.get_address())
		intreturn_bytecode = ByteCode(INTERNAL_RETURN_OPCODE, "gg", bytecode_0.get_address())
		new_block.append(intreturn_bytecode)
		new_block.__block_id = self.get_id()
		# new_block.debug_block()

		return new_block

	def merge(self, other):
		exit_bytecode = self.get_exit_bytecode()
		if exit_bytecode.opcode == "JUMP":
			exit_bytecode.opcode = "POP"
		for bytecode in other:
			self.append(bytecode)

	def is_empty(self):
		return len(self.__items) == 0

	def get_block_hash(self):
		raw_bytes = list()
		for bytecode in self:
			raw_byte = bytecode.raw_byte
			raw_bytes.append(raw_byte)
		raw_string = array.array('B', raw_bytes).tostring()
		m = hashlib.md5()
		m.update(raw_string)
		return int(m.hexdigest(), 16)

	def make_copy(self, block_id=-1):
		other = BytecodeBlock(block_id)
		other.__items = deepcopy(self.__items)
		return other

	def debug_block(self, depth=0):
		print("\nblock_%d" % self.get_id())
		for bytecode in self:
			print(bytecode)

	def __str__(self):
		return "block_%d" % self.get_id()

	def __iter__(self):
		for item in self.__items:
			yield item
