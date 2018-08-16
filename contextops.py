from ceptions import ValidationError
from ceptions import PoisonException
from opcodes import order_ops

READ_POISON = ('READ', -1)


class ContextOps:
	def __init__(self):
		self.__maps = [dict()]

	def push_context(self, separator):
		self.__maps.append(separator)
		self.__maps.append(dict())

	def pop_context(self, separator):
		current = self.__maps[0]
		if len(self.__maps) == 1:
			if READ_POISON in current:
				raise PoisonException("poison encountered")
			raise ValidationError("write operation not synced")

		self.__maps.pop(0)    # pop context
		expected = self.__maps.pop(0)  # pop separator

		if expected != separator:
			raise ValidationError("write operation not synced")

	def add_mapping(self, k, v):
		if k in self.__maps[-1]:
			w = self.__maps[-1][k]
			if w != v:
				print("[WARNING] overwriting entry")
		self.__maps[-1][k] = v

	def lookup_mapping(self, k):
		if k not in self.__maps[0]:
			if READ_POISON in self.__maps[0]:
				raise PoisonException("poison encountered")
			raise ValidationError("read operation not synced")
		return self.__maps[0][k]

	def debug_mapping(self):
		for i, item in enumerate(self.__maps):
			if i % 2 == 0:
				print("")
			if isinstance(item, dict):
				for k, v in item.items():
					print(k, v)
			else:
				print(item)

	def check_end_mapping(self):
		return READ_POISON in self.__maps[0]


class FreeOps:
	def __init__(self):
		self.__map = dict()

	def add_mapping(self, k, v):
		opcode = k[0]
		if opcode in order_ops:
			if k not in self.__map:
				self.__map[k] = list()
			# print(opcode)
			self.__map[k].append(v)
		else:
			if k in self.__map and self.__map[k] != v:
				print("[WARNING] overwriting free ops mapping")
			self.__map[k] = v

	def in_mapping(self, k):
		return k in self.__map

	def lookup_mapping(self, k):
		v = self.__map[k]
		if isinstance(v, list):
			if len(v) == 1:
				return v[0]
			return v.pop(0)     # still bad
		else:
			return v

	def debug_mapping(self):
		for k, v in self.__map.items():
			print(k, v)


class EffectOps:
	def __init__(self):
		self.__map = dict()
		self.__hit = set()

	def add_mapping(self, k, v):
		if k not in self.__map:
			self.__map[k] = list()
		self.__map[k].append(v)

	def lookup_mapping(self, k):
		if k not in self.__map:
			if self.reached_end_state():
				raise PoisonException("poison encountered")
			else:
				raise KeyError(k)

		v = self.__map[k]
		if len(v) == 1:
			self.__hit.add(k)
			return v[0]
		return v.pop(0)

	def debug_mapping(self):
		for k, v in self.__map.items():
			print(k)

	def reached_end_state(self):
		return len(self.__hit) == len(self.__map)
