from copy import deepcopy

INTERNAL_CALL_OPCODE = "INTCALL"
INTERNAL_RETURN_OPCODE = "INTRETURN"

SWAP_REGISTER = "$t"
STACK_REGISTER = "$s"


def to_stack_registers(items):
	return [STACK_REGISTER + str(i) for i in items]


class Instruction:
	def __init__(self, opcode, reads, writes, address):
		self.opcode = opcode
		# must deep copy
		self.reads = deepcopy(reads)
		self.writes = deepcopy(writes)
		self.address = address

	def rename_read_register(self, old_name, new_name):
		for index, register in enumerate(self.reads):
			if register == old_name:
				self.reads[index] = new_name

	def rename_write_register(self, old_name, new_name):
		for index, register in enumerate(self.writes):
			if register == old_name:
				self.writes[index] = new_name

	def read_to_string(self, index):
		return str(self.reads[index])

	def reads_from(self, register):
		return register in self.reads

	def writes_to(self, register):
		return register in self.writes

	def reads_to_string(self):
		return ", ".join([str(i) for i in self.reads])

	def writes_to_string(self):
		return ", ".join([str(i) for i in self.writes])

	def get_read_registers(self):
		return set([i for i in self.reads if isinstance(i, str)])

	def get_write_registers(self):
		return set(self.writes)

	def set_constant(self, tar_register, constant):
		for index, register in enumerate(self.reads):
			if register == tar_register:
				self.reads[index] = constant

	def is_constant_move(self):
		return self.opcode == "MOVE" and not isinstance(self.reads[0], str)

	def is_register_move(self):
		return self.opcode == "MOVE" and isinstance(self.reads[0], str)

	def get_constants(self):
		constants = list()
		for register in self.reads:
			if isinstance(register, str):
				return None
			constants.append(register)
		return constants

	def __str__(self):
		reads = self.reads_to_string()
		writes = self.writes_to_string()
		if reads == "":
			return self.opcode + "\t" + writes
		if writes == "":
			return self.opcode + "\t" + reads
		return self.opcode + "\t" + writes + ", " + reads


class MoveInstruction(Instruction):
	def __str__(self):
		return "MOVE\t%s, %s" % (self.writes[0], self.reads_to_string())


class MonoOpInstruction(Instruction):
	def __str__(self):
		return "%s\t%s, %s" % (self.opcode, self.writes[0], self.reads_to_string())


class BinOpInstruction(Instruction):
	def __str__(self):
		return "%s\t%s, %s" % (self.opcode, self.writes[0], self.reads_to_string())


class MloadInstruction(Instruction):
	def __str__(self):
		return "MLOAD\t%s, [%s]" % (self.writes[0], self.reads_to_string())


class MstoreInstruction(Instruction):
	def __str__(self):
		return "MSTORE\t%s, [%s]" % (self.read_to_string(1), self.read_to_string(0))


class SloadInstruction(Instruction):
	def __str__(self):
		return "SLOAD\t%s, [%s]" % (self.writes[0], self.reads_to_string())


class SstoreInstruction(Instruction):
	def __str__(self):
		return "SSTORE\t%s, [%s]" % (self.read_to_string(1), self.read_to_string(0))


class CallLoadInstruction(Instruction):
	def __str__(self):
		return "CLOAD\t%s, [%s]" % (self.writes[0], self.reads_to_string())


class IntCallInstruction(Instruction):
	def __str__(self):
		return "%s %s\t%s" % (self.opcode, self.writes_to_string(), self.reads_to_string())


class NopInstruction(Instruction):
	def __init__(self, address):
		Instruction.__init__(self, "NOP", [], [], address)


# class SHA3Operation(Instruction):
# 	def __init__(self, reads, writes, address):
# 		Instruction.__init__(self, "SHA3R", reads, writes, address)


# class AssertOperation(Instruction):
# 	def __init__(self, reads, writes, address):
# 		Instruction.__init__(self, "ASSERT", reads, writes, address)

