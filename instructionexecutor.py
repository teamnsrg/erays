from baseexecutor import BaseExecutor
from opcodes import call_ops


class InstructionExecutor(BaseExecutor):
	def __init__(self, reader, lifter, debug):
		BaseExecutor.__init__(self, reader, lifter, debug)

	def load_inputs(self, instruction, depth=0):
		opcode = instruction.opcode
		inputs = [opcode]
		for read in instruction.reads:
			if isinstance(read, str):
				inputs.append(self.registers[read])
			else:
				inputs.append(read)

		if opcode in call_ops:
			del inputs[1]
		return tuple(inputs)
