from bytecodeblock import *
from ceptions import *
from opcodes import *
from bytecodes import *

from itertools import groupby
import sys, re


class Disassembler(object):
	def __init__(self, binary):
		if len(binary) == 0:
			raise InputError("empty hex string")
		binary += "00"
		self.__detect_swarm_hash(binary)
		self.raw_bytes = list()
		for i in range(0, len(binary), 2):
			try:
				byte = int(binary[i:i + 2], 16)
			except ValueError:
				raise InputError("illegal hex character")
			self.raw_bytes.append(byte)

		self.bytecodes = dict()
		# self.__call_addresses = set()
		self.__decode_bytecodes()

		self.__block_count = 0
		self.__basic_blocks = dict()
		self.__addresses = dict()
		self.jump_dests = dict()

		self.__create_basic_blocks()
		self.__simplify_assertions()

	def __detect_swarm_hash(self, binary):
		binary_length = len(binary)
		if binary_length % 2 != 0:
			raise InputError("odd length binary")
		# 0xa1 0x65 'b' 'z' 'z' 'r' '0'
		swarm_pattern = re.compile("a165627a7a7230")
		match = re.search(swarm_pattern, binary)
		if not match:
			self.swarm_hash_address = binary_length / 2
		else:
			self.swarm_hash_address = int(match.start() / 2)

	def __decode_data(self, begin, end):
		data = self.raw_bytes[begin: end]
		data = [hex(d)[2:] for d in data]
		data = [d.zfill(2) for d in data]
		data = "".join(data)
		try:
			return int(data, 16)
		except ValueError:
			return 0

	def __decode_bytecodes(self):
		address = 0
		while address < self.swarm_hash_address:
			raw_byte = self.raw_bytes[address]

			if raw_byte in opcodes:
				opcode = opcodes[raw_byte]
			else:
				opcode = "GARBAGE"

			bytecode = self.decode_bytecode(opcode, address, raw_byte)
			self.bytecodes[address] = bytecode

			if opcode in push_ops:
				gamma = actions[opcode][-1]
				data = self.__decode_data(address + 1, address + gamma + 1)
				bytecode.set_dependency(0, data)
				address += gamma

			address += 1

	@staticmethod
	def decode_bytecode(opcode, address, raw_byte):
		if opcode in push_ops:
			bytecode = PushByteCode(opcode, raw_byte, address)
		elif opcode in bin_ops:
			bytecode = BinOpByteCode(opcode, raw_byte, address)
		elif opcode in mono_ops:
			bytecode = MonoOpByteCode(opcode, raw_byte, address)
		else:
			bytecode = ByteCode(opcode, raw_byte, address)
		return bytecode

	def __create_basic_blocks(self):
		header_addresses, split = set(), False
		for address in sorted(self.bytecodes):
			bytecode = self.bytecodes[address]
			if bytecode.is_jumpdest() or split:
				header_addresses.add(address)
				split = False

			if bytecode.opcode in exit_ops \
				or bytecode.opcode in jump_ops:
				split = True

		basic_block = BytecodeBlock(self.__block_count)
		for address in sorted(self.bytecodes):
			bytecode = self.bytecodes[address]
			if address in header_addresses and address != 0:
				self.__basic_blocks[basic_block.get_id()] = basic_block
				self.__block_count += 1
				basic_block = BytecodeBlock(self.__block_count)
			if bytecode.is_jumpdest():
				self.jump_dests[address] = basic_block.get_id()
			basic_block.append(bytecode)
			self.__addresses[address] = basic_block.get_id()
		self.__basic_blocks[basic_block.get_id()] = basic_block

	def __simplify_assertions(self):
		block_ids = sorted(self.__basic_blocks.keys())
		for i in range(len(block_ids) - 1):
			id_0, id_1 = block_ids[i:i+2]
			block_0 = self.__basic_blocks[id_0]
			block_1 = self.__basic_blocks[id_1]
			address = block_0.get_jumpi_address()
			if address is not None and block_1.is_abort_block():
				block_0.insert_assert()

	def debug_bytecodes(self):
		for block_id in self.__basic_blocks:
			basic_block = self.__basic_blocks[block_id]
			basic_block.debug_block()

	def get_raw_bytes(self, b=0, e=-1):
		if e == -1:
			return self.raw_bytes[b::]
		return self.raw_bytes[b:e]

	def get_swarm_hash_bytes(self):
		return self.raw_bytes[self.swarm_hash_address:]

	def get_blocks(self):
		return self.__basic_blocks

	def get_opcode_bytes(self):
		opcode_bytes = list()
		for address in sorted(self.bytecodes):
			instruction = self.bytecodes[address]
			opcode_byte = instruction.raw_byte
			opcode_byte = hex(opcode_byte)[2:].zfill(2)
			opcode_bytes.append(opcode_byte)
		opcode_bytes = "".join(opcode_bytes)
		return opcode_bytes

	def get_block_trace(self, program_counters):
		block_trace = [self.__addresses[pc] for pc in program_counters]
		block_trace = [x[0] for x in groupby(block_trace)]
		return block_trace


if __name__ == "__main__":
	with open(sys.argv[1]) as f:
		line = f.readline().strip()
	dis = Disassembler(line)
	dis.debug_bytecodes()
