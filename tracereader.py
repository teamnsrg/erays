from opcodes import *
from ceptions import TraceError, TraceException, ValidationError, InputError
from contextops import ContextOps, FreeOps, READ_POISON, EffectOps


from graphbuilder import FALLBACK_SIGNATURE

import sys, json


def load_trace(line):
	if len(line) > 1073741824:
		raise InputError("JSON too large")
	try:
		info = json.loads(line)
	except ValueError:
		raise InputError("JSON failed to parse")

	if 'error' in info:
		raise InputError("JSON missing transaction")
	return info


class TraceReader:
	def __init__(self, line):
		info = load_trace(line)
		self.code = info['code']
		self.__parse_signature(info)
		self.error = info['result']['failed']

		self.free_ops = FreeOps()
		self.memory_ops = ContextOps()
		self.storage_ops = ContextOps()

		t_ = info['result']['structLogs']
		self.trace = [i for i in t_ if i['depth'] == 1]

	def __parse_signature(self, info):
		signature = info['input_data'][:10]
		if signature == "0x":
			self.signature = FALLBACK_SIGNATURE
		else:
			self.signature = int(signature, 16)

	def parse_trace(self):
		self.__parse_trace()

	def __parse_trace(self):
		for index, item in enumerate(self.trace):
			opcode = item['op'].encode('utf-8')

			try:
				inputs, output = self.get_pair(opcode, index)
			except TraceException:
				self.trace = self.trace[:index]
				self.error = True
				break

			if opcode in free_ops:
				self.free_ops.add_mapping(inputs, output)
			if opcode in mem_read_ops:      # mem reads/writes are not mutually exclusive
				self.memory_ops.add_mapping(inputs, output)
			if opcode in mem_write_ops:     # there will be one in the context, and another as separator
				self.memory_ops.push_context(inputs)
			if opcode == "SLOAD":
				self.storage_ops.add_mapping(inputs, output)
			elif opcode == "SSTORE":
				self.storage_ops.push_context(inputs)
			if 'error' in item:
				self.error = True

		self.memory_ops.add_mapping(READ_POISON, (-1,))
		self.storage_ops.add_mapping(READ_POISON, (-1,))
		# self.__memory_ops.debug_contexts()

	def get_pair(self, opcode, index):
		if "0xfe" in opcode:
			opcode = "INVALID"
		delta, alpha = actions[opcode][:2]
		output = self.get_stack_items(index + 1, alpha)
		inputs = self.get_stack_items(index, delta)
		if opcode in call_ops:
			inputs = tuple([opcode] + inputs[1:])  # we do not care gas value
		else:
			inputs = tuple([opcode] + inputs)

		if len(output) == 1:
			output = output[0]
		else:
			output = None
		return inputs, output

	def get_stack_items(self, index, count=1):
		if count == 0:
			return []
		try:
			values = self.trace[index]['stack'][-count:]
		except IndexError:
			raise TraceException("trace ends with error")
		return [int(v, 16) for v in reversed(values)]

	# TODO: how to fix this stupid forwarding
	def fast_forward_trace(self, begin_address):
		begin = -1
		# print(begin_address)
		for index, item in enumerate(self.trace):
			opcode = item['op'].encode('utf-8')
			try:
				inputs, _ = self.get_pair(opcode, index)
			except TraceException:
				break
			if opcode in mem_write_ops:
				self.memory_ops.pop_context(inputs)

			if item['pc'] == begin_address:
				begin = index
				break

		if begin == -1 or len(self.trace) == 0:
			if self.error:
				raise TraceError("trace did not reach function entry")
			raise ValidationError("failed to reach entry")
		self.trace = self.trace[begin:]

	def get_cur_state(self):
		# print (self.trace[0])
		return self.trace[0]

	def do_mread(self, inputs):
		return self.memory_ops.lookup_mapping(inputs)

	def do_mwrite(self, inputs):
		self.memory_ops.pop_context(inputs)

	def do_sload(self, inputs):
		return self.storage_ops.lookup_mapping(inputs)

	def do_sstore(self, inputs):
		self.storage_ops.pop_context(inputs)

	def debug_mem_contexts(self):
		self.memory_ops.debug_mapping()


class EffectReader(TraceReader):
	def __init__(self, line):
		TraceReader.__init__(self, line)

		self.free_ops = FreeOps()
		self.storage_ops = ContextOps()
		self.memory_ops = dict()  # this is pretty bad
		self.effect_ops = EffectOps()

	def parse_trace(self):
		self.__parse_trace()
		# self.storage_ops.debug_mapping()

	def __parse_trace(self):
		for index, item in enumerate(self.trace):
			opcode = item['op'].encode('utf-8')
			# print(index)
			try:
				inputs, output = self.get_pair(opcode, index)
			except TraceException:
				self.trace = self.trace[:index]
				self.error = True
				break

			if opcode in free_ops:
				self.free_ops.add_mapping(inputs, output)
			elif opcode in effect_ops:
				self.__parse_effect_op(index, opcode, inputs, output)
			# if it still interacts with memory
			elif opcode in mem_read_ops | mem_write_ops:
				self.__parse_memory_ops(index, opcode, inputs, output)
			elif opcode == "SLOAD":
				self.storage_ops.add_mapping(inputs, output)
			elif opcode == "SSTORE":
				self.storage_ops.push_context(inputs)
			if 'error' in item:
				self.error = True
		# self.effect_ops.debug_mapping()
		self.storage_ops.add_mapping(READ_POISON, (-1,))

	def get_memory_bytes(self, index, offset, size):
		memory = self.trace[index]['memory']
		memory = "".join(memory)
		begin, end = offset * 2,(offset + size) * 2
		return memory[begin:end].encode('utf-8')

	def __parse_effect_op(self, index, opcode, inputs, output):
		if opcode in log_ops | {"RETURN"}:
			offset, size = inputs[1], inputs[2]
			chunk = self.get_memory_bytes(index, offset, size)
			inputs = tuple([opcode, chunk] + list(inputs[3:]))
			self.effect_ops.add_mapping(inputs, output)
		elif opcode in call_ops: 			# gas is already removed
			# to [1], value [2], in offset [-4], in_size [-3], out_offset [-2], out_size [-1]
			in_offset, in_size = inputs[-4], inputs[-3]
			in_chunk = self.get_memory_bytes(index, in_offset, in_size)
			out_offset, out_size = inputs[-2], inputs[-1]
			out_chunk = self.get_memory_bytes(index + 1, out_offset, out_size)
			output = (output, out_chunk)
			if opcode == "DELEGATECALL":
				inputs = (opcode, inputs[1], in_chunk, out_offset, out_size)
			else:
				inputs = (opcode, inputs[1], inputs[2], in_chunk, out_offset, out_size)
			self.effect_ops.add_mapping(inputs, output)
		elif opcode == "CREATE":
			offset, size = inputs[2], inputs[3]
			chunk = self.get_memory_bytes(index, offset, size)
			inputs = (opcode, chunk)
			self.effect_ops.add_mapping(inputs, output)
		else:
			raise NotImplementedError("effect op " + opcode + "not parsed")

	def __parse_memory_ops(self, index, opcode, inputs, output):
		if opcode == "SHA3":
			offset, size = inputs[1], inputs[2]  # get the real input
			chunk = self.get_memory_bytes(index, offset, size)
			inputs = (opcode, chunk)
			# print(inputs)
			self.memory_ops[inputs] = output
		elif opcode == "CALLDATACOPY":
			offset, size = inputs[1], inputs[3]
			chunk = self.get_memory_bytes(index + 1, offset, size)
			self.memory_ops[inputs] = chunk
		elif opcode == "CODECOPY":
			offset, size = inputs[1], inputs[3]
			chunk = self.get_memory_bytes(index + 1, offset, size)
			self.memory_ops[inputs] = chunk
		elif opcode == "EXTCODECOPY":
			offset, size = inputs[2], inputs[4]
			chunk = self.get_memory_bytes(index + 1, offset, size)
			self.memory_ops[inputs] = chunk
		# print(self.trace[index+1])
		elif opcode not in {"MLOAD", "MSTORE", "MSTORE8"}:
			raise NotImplementedError("memory op " + opcode + " not parsed")

	def fast_forward_trace(self, begin_address):
		begin = -1
		for index, item in enumerate(self.trace):
			opcode = item['op'].encode('utf-8')
			try:
				inputs, _ = self.get_pair(opcode, index)
			except TraceException:
				break

			if item['pc'] == begin_address:
				begin = index
				break

		if begin == -1 or len(self.trace) == 0:
			if self.error:
				raise TraceError("trace did not reach function entry")
			raise ValidationError("failed to reach entry")
		self.trace = self.trace[begin:]

	def do_mem_ops(self, inputs):
		return self.memory_ops[inputs]

	def do_effect_ops(self, inputs):
		return self.effect_ops.lookup_mapping(inputs)

	def do_end_check(self):
		return self.effect_ops.reached_end_state()


if __name__ == "__main__":
	line = open(sys.argv[1]).readline()
	t = EffectReader(line)
	t.parse_trace()

	# file = open(sys.argv[1])
	# for count, line in enumerate(file):
	# 	if count == 100:
	# 		break
	# 	try:
	# 		print(count)
	# 		t = EffectReader(line)
	# 		t.parse_trace()
	# 	except:
	# 		pass
