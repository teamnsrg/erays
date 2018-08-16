from ceptions import MemoryException

ARRAY_SIZE_MAGIC = 1024   # enough for most cases
ZERO_WORD = "0000000000000000000000000000000000000000000000000000000000000000"


class MemoryModel:
	def __init__(self, chunk):
		# print(chunk)
		self.__array = bytearray(chunk + ZERO_WORD * ARRAY_SIZE_MAGIC)

	def load_as_str(self, offset, size):
		return str(self.load(offset, size))

	def load_as_int(self, offset):
		return int(str(self.load(offset)), 16)

	def load(self, offset, size=32):
		begin, end = offset * 2, (offset + size) * 2
		if end > len(self.__array):
			# print(end, len(self.__array))
			raise MemoryException("out of bound access")
		return self.__array[begin:end]

	def store(self, offset, size, value):
		begin, end = offset * 2, (offset + size) * 2
		self.__array[begin:end] = value

	def debug_memory(self):
		arr = str(self.__array)
		arr = [arr[i:i + 64] for i in range(0, len(arr), 64)]
		for i in arr:
			print(i)
