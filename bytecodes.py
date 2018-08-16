from opcodes import mono_ops
from opcodes import bin_ops


class ByteCode(object):
	def __init__(self, opcode, raw_byte, major_ad, minor_ad=0):
		self.opcode = opcode
		self.raw_byte = raw_byte
		self.__major_ad = major_ad
		self.__minor_ad = minor_ad
		self.dependencies = dict()
		# this is bad, but this is here
		self.__block_id = -1

	def set_container_block_id(self, block_id):
		self.__block_id = block_id

	def get_container_block_id(self):
		return self.__block_id

	def get_str_address(self):
		str_ad = hex(self.__major_ad)[2:]
		if self.__minor_ad > 0:
			str_ad += "+" + str(self.__minor_ad)
		elif self.__minor_ad < 0:
			str_ad += str(self.__minor_ad)
		return str_ad

	def get_address(self):
		return self.__major_ad

	def reset_dependencies(self):
		self.dependencies = dict()

	def set_dependency(self, pos, node):
		self.dependencies[pos] = node

	def is_jumpdest(self):
		return self.opcode == "JUMPDEST"

	def is_jump(self):
		return self.opcode == "JUMP"

	def __str__(self):
		return "0x%s\t%s" % (self.get_str_address(), self.opcode)


class PushByteCode(ByteCode):
	def __init__(self, opcode, raw_byte, major_ad, minor_ad=0):
		ByteCode.__init__(self, opcode, raw_byte, major_ad, minor_ad)

	def reset_dependencies(self):
		# override to do nothing
		pass

	def get_value(self):
		return self.dependencies[0]

	def __str__(self):
		value_str = "\t\t0x%x" % self.dependencies[0]
		return ByteCode.__str__(self) + value_str


class MonoOpByteCode(ByteCode):
	def __init__(self, opcode, raw_byte, major_ad):
		ByteCode.__init__(self, opcode, raw_byte, major_ad)
		self.operator = mono_ops[self.opcode]


class BinOpByteCode(ByteCode):
	def __init__(self, opcode, raw_byte, major_ad):
		ByteCode.__init__(self, opcode, raw_byte, major_ad)
		self.operator = bin_ops[self.opcode]
