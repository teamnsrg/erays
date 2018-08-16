from expressions import PassExpression


def get_prefix(depth):
	return "  " * depth


class ExpressionBlock:
	def __init__(self, block_id, entry_addr):
		self.__block_id = block_id
		self.__entry_address = entry_addr
		# self.exit_stack_size = basic_block.exit_stack_size

		self.__expressions = list()
		self.exit_stack_size = -1

	def get_id(self):
		return self.__block_id

	def append_expression(self, expression):
		self.__expressions.append(expression)

	def get_entry_address(self):
		return self.__entry_address

	def get_exit_address(self):
		if len(self.__expressions) == 0:
			return self.__entry_address
		return self.__expressions[-1].address

	def set_pass_expression(self, index):
		address = self.__expressions[index].address
		self.__expressions[index] = PassExpression(address)

	def check_exit_expression(self, opcode):
		if len(self.__expressions) == 0:
			return False
		return self.__expressions[-1].opcode == opcode

	def get_block(self, block_id):
		if self.get_id() == block_id:
			return self

	def remove_end_jump(self):
		if len(self.__expressions) != 0 \
			and self.__expressions[-1].opcode == "JUMP":
			self.__expressions = self.__expressions[:-1]

	def debug_block(self, depth=0):
		prefix = get_prefix(depth)
		print(prefix + str(self.__block_id))
		print(prefix + hex(self.get_entry_address()))
		for i, expression in enumerate(self.__expressions):
			print(prefix + str(i) + "\t" + str(expression).lower())
		print("")

	def get_items(self):
		return self.__expressions

	def set_items(self, items):
		self.__expressions = items

	def __iter__(self):
		for expression in self.__expressions:
			yield expression

	def dot_format_block(self, depth=0, suppress=False):
		# print(depth)
		prefix = get_prefix(depth)
		results = []
		for expression in self.__expressions:
			results.append(prefix + str(expression))
		return "\l".join(results) + "\l"

	def dot_format_if_header(self, depth):
		prefix = get_prefix(depth)
		results = []
		for i, expression in enumerate(self.__expressions):
			if i == len(self.__expressions) - 1:
				results.append(prefix + expression.get_inverted_condition() + "{")
			else:
				results.append(prefix + str(expression))
		return "\l".join(results) + "\l"

	def dot_format_while_header(self, depth):
		prefix = get_prefix(depth)
		results = []
		for i, expression in enumerate(self.__expressions):
			if i == len(self.__expressions) - 1:
				results.append(prefix + expression.get_condition())
				results.append(prefix + "\tbreak")
			else:
				results.append(prefix + str(expression))
		return "\l".join(results) + "\l"





