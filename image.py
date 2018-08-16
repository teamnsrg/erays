from bytecodes import *
from ceptions import IllegalInstructionError
from opcodes import actions, dup_ops, swap_ops


def union(list_1, list_2):
	if list_1 == list_2:
		return list_1
	if isinstance(list_1, ByteCode):
		list_1 = [list_1]
	if isinstance(list_2, ByteCode):
		list_2 = [list_2]
	return list(set(list_1) | set(list_2))


class Image(object):
	def __init__(self, id_str, other=None):
		self.block_id = id_str
		self.stack = dict()
		self.top = 0
		if not other:
			return
		for k in other.stack:
			self.stack[k] = other.stack[k]
		self.top = other.top

	def debug_stack(self):
		for pos in sorted(self.stack.keys()):
			print("%d\t%s" % (pos, str(self.stack[pos])))
		print("")

	def interpret_bytecode(self, bytecode):
		opcode = bytecode.opcode
		if opcode not in actions:
			raise IllegalInstructionError("GARBAGE bytcode encountered")

		delta = actions[opcode][0]
		alpha = actions[opcode][1]

		reads = [self.top - i - 1 for i in range(delta)]
		writes = [self.top - delta + i for i in range(alpha)]

		if opcode in dup_ops:
			self.stack[self.top] = self.stack[self.top - delta]
			self.top = self.top - delta + alpha
			return

		if opcode in swap_ops:
			read1, read2 = self.top - delta, self.top - 1
			temp = self.stack[read1]
			self.stack[read1] = self.stack[read2]
			self.stack[read2] = temp
			return

		self.top = self.top - delta + alpha

		for i, stack_pos in enumerate(reads):
			bytecode.set_dependency(i, self.stack.pop(stack_pos))

		for stack_pos in writes:
			self.stack[stack_pos] = bytecode

	# make a copy, but not really a deep copy
	def make_copy(self):
		other = Image(self.block_id)
		other.top = self.top
		stack_1, stack_2 = self.stack, other.stack
		for pos, instructions in stack_1.items():
			stack_2[pos] = instructions
		return other

	# combine two different stacks
	def __add__(self, other):
		if self.top != other.top:
			raise RuntimeWarning("[WARNING] stack pointer not matched")

		temp, stack = Image(self.top), dict()
		stack_1, stack_2 = self.stack, other.stack
		for pos, instructions in stack_1.items():
			stack[pos] = instructions

		for pos, instructions in stack_2.items():
			if pos in stack:
				result = union(stack[pos], instructions)
				stack[pos] = result
			else:
				stack[pos] = instructions
		temp.stack = stack
		return temp

	def __eq__(self, other):
		if self.top != other.top:
			return False
		for i in range(self.top):
			# try:
			if isinstance(self.stack[i], PushByteCode)\
				and self.stack[i] != other.stack[i]:
				return False
			# except KeyError:
			# 	raise DependencyError
		return True
