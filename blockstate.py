from opcodes import mem_write_ops, mem_read_ops, order_ops, throw_away_ops

TOP = 'T'


class BlockState:
	def __init__(self):
		self.mapping = dict()

	def debug_state(self):
		print("-" * 32)
		for reg, val in self.mapping.items():
			# if val != TOP:
			print("\t" + reg + " : " + str(val))
		print("-" * 32)

	def __eq__(self, other):
		return self.mapping == other.mapping


class ConstantState(BlockState):
	def join(self, other):
		for reg, val2 in other.mapping.items():
			if reg not in self.mapping:
				self.mapping[reg] = val2
			val1 = self.mapping[reg]
			if val2 != val1:
				self.mapping[reg] = TOP

	def add_mapping(self, instruction):
		if instruction.is_constant_move():
			write = instruction.writes[0]
			val = instruction.reads[0]
			self.mapping[write] = val
		else:
			for write in instruction.writes:
				self.mapping[write] = TOP  # cannot model

	def apply_mapping(self, instruction):
		for reg, val in self.mapping.items():
			if val != TOP:
				instruction.set_constant(reg, val)


class CopyState(BlockState):
	def join(self, other):
		for reg, val2 in other.mapping.items():
			if reg not in self.mapping:
				self.mapping[reg] = val2
			val1 = self.mapping[reg]
			if val2 != val1:
				self.mapping[reg] = TOP

	def add_mapping(self, instruction):
		if instruction.is_register_move():
			write = instruction.writes[0]
			read = instruction.reads[0]
			self.mapping[write] = read
		else:
			for write in instruction.writes:
				self.mapping[write] = TOP  # first kill write

		# then kill all invalidated copies
		for write in instruction.writes:
			for k, v in self.mapping.items():
				if v == write:
					self.mapping[k] = TOP

	def apply_mapping(self, instruction):
		for read in instruction.reads:
			if read in self.mapping:
				new_name = self.mapping[read]
				if new_name == TOP:
					continue
				instruction.rename_read_register(read, new_name)


class MemState(BlockState):
	def add_mapping(self, index, instruction):
		opcode = instruction.opcode
		if opcode in mem_write_ops:
			if opcode == "MSTORE":
				address, value = instruction.reads
				if not isinstance(address, str):
					self.mapping[address] = (value, index)
					return
			self.mapping.clear()
		else:
			for write in instruction.writes:
				for k, (v, i) in self.mapping.items():
					if v == write:
						del self.mapping[k]

	def lookup_mapping(self, addresses):
		values = list()
		for address in addresses:
			if address in self.mapping:
				values.append(self.mapping[address])
			else:
				return list()
		return values


class ExpressionState(BlockState):
	def apply_mapping(self, expression):
		for r, e in self.mapping.items():
			expression.set_dependency(r, e)

		# if expression.opcode == "SSTORE":
		# 	self.clear_entries({"SLOAD"})
		# 	return
		# if expression.contains_operations(mem_write_ops):
		# 	self.clear_entries(mem_read_ops)
		# 	return
		# return

	def add_mapping(self, expression):
		writes = expression.writes
		if len(writes) == 0:
			return
		for write in expression.writes:
			for r, e in self.mapping.items():
				if e.reads_register(write):
					self.remove_mapping(r)
			self.remove_mapping(write)

		if expression.opcode not in throw_away_ops:
			return
		register = expression.writes[0]
		if expression.reads_register(register):
			return
		self.mapping[register] = expression

	def remove_mapping(self, register):
		if register in self.mapping:
			del (self.mapping[register])

	def clear_entries(self, operations):
		for r, e in self.mapping.items():
			if e.contains_operations(operations):
				del (self.mapping[r])
