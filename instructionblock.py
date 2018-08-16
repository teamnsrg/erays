from copy import deepcopy

from instructions import NopInstruction


class InstructionBlock:
	def __init__(self, major_id, entry_addr):
		self.__block_id = major_id
		self.__entry_address = entry_addr
		self.__instructions = list()

		# self.phi_functions = dict()

		# self.__stack_size = stack_size
		self.exit_stack_size = -1

	def append(self, inst):
		self.__instructions.append(inst)

	def get_id(self):
		return self.__block_id

	def get_entry_address(self):
		return self.__entry_address

	# def has_phi_function(self, register):
	# 	return register in self.phi_functions \
	# 		or register not in self.entry_registers
	#
	# def insert_phi_function(self, register, pre_ids):
	# 	if register not in self.entry_registers:
	# 		return
	# 	phi_function = dict()
	# 	for pre_id in pre_ids:
	# 		phi_function[pre_id] = register
	# 	self.phi_functions[register] = phi_function
	# 	return
	#
	# def update_phi_function(self, pre_id, register, new_register):
	# 	if register not in self.phi_functions:
	# 		print("no such phi function")
	# 		return
	# 	phi_function = self.phi_functions[register]
	# 	if pre_id not in phi_function:
	# 		print("no such pre_id")
	# 		return
	# 	phi_function[pre_id] = new_register
	# 	return
	#
	# def debug_phi_functions(self):
	# 	for r, phi in self.phi_functions.items():
	# 		print(r),
	# 		print(phi)
	# 	print("")

	def debug_block(self, depth=0):
		print("\nblock_%d" % self.get_id())
		# self.debug_phi_functions()
		print(self.__entry_address)
		for instruction in self.__instructions:
			print(str(instruction.address) + "\t" + str(instruction).lower())
		# print(" ".join(self.exit_registers))

	def get_instructions(self):
		return self.__instructions

	def set_instructions(self, instructions):
		self.__instructions = instructions

	def set_instruction(self, index, instruction):
		self.__instructions[index] = instruction

	def set_nop_instruction(self, index):
		original = self.__instructions[index]
		self.__instructions[index] = NopInstruction(original.address)

	def check_exit_instruction(self, opcode):
		if len(self.__instructions) == 0:
			return False
		return self.__instructions[-1].opcode == opcode

	def get_exit_address(self):
		if len(self.__instructions) == 0:
			return self.__entry_address
		return self.__instructions[-1].address

	# def get_exit_instruction(self):
	# 	if len(self.__instructions) == 0:
	# 		return None
	# 	return self.__instructions[-1]

	def merge(self, other):
		# exit_bytecode = self.get_exit_bytecode()
		if self.check_exit_instruction("JUMP"):
			self.set_nop_instruction(-1)
		# if self.check_exit_instruction("JUMPI"):
		# 	print("defauq")
		for instruction in other:
			self.append(instruction)

	def make_copy(self, block_id=-1):
		other = InstructionBlock(block_id, self.__entry_address)
		other.__instructions = deepcopy(self.__instructions)
		return other

	def __iter__(self):
		for instruction in self.__instructions:
			yield instruction

	def __str__(self):
		return "block_" + str(self.__block_id)
