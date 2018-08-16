class JumpAddressError(Exception):
	pass


class StackSizeError(Exception):
	pass


class InstructionAddressError(Exception):
	pass


class IllegalInstructionError(Exception):
	pass


class DependencyError(Exception):
	pass


class TraceError(Exception):
	pass


class InternalFunctionError(Exception):
	pass


class TimeoutException(Exception):
	pass


class ValidationError(Exception):
	pass


class InputError(Exception):
	pass


class OperationError(Exception):
	pass


class PoisonException(Exception):
	pass


class TraceException(Exception):
	pass


class MemoryException(Exception):
	pass

