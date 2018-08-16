from baseexecutor import BaseExecutor
from opcodes import call_ops


class ExpressionExecutor(BaseExecutor):
	def __init__(self, reader, lifter, debug):
		BaseExecutor.__init__(self, reader, lifter, debug)

	def load_inputs(self, expression, depth=0):
		opcode = expression.opcode
		inputs = [opcode]
		for i, read in enumerate(expression.reads):
			if isinstance(read, str):
				dependency = expression.get_dependency(i)
				if dependency is not None:
					sub_inputs = self.load_inputs(dependency, depth + 1)
					sub_output = \
						self.execute_opcode(dependency.opcode, sub_inputs)
					inputs.append(sub_output)
				else:
					inputs.append(self.registers[read])
			else:
				inputs.append(read)
		if opcode in call_ops:
			del inputs[1]
		return tuple(inputs)
