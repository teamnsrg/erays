from instructionexecutor import InstructionExecutor
from rewriter import Rewriter
from tracereader import EffectReader, TraceReader
from ceptions import TimeoutException

import signal, sys


def handler(signum, frame):
	raise TimeoutException("timeout")


class RewriterTester:
	def __init__(self, line):
		reader = EffectReader(line)
		# reader = TraceReader(line)
		reader.parse_trace()
		self.code_size = len(reader.code)

		signal.signal(signal.SIGALRM, handler)
		signal.alarm(15)
		# print(reader.signature)
		rewriter = Rewriter(reader.code)
		InstructionExecutor(reader, rewriter)
		signal.alarm(0)

	def get_code_size(self):
		return self.code_size


if __name__ == "__main__":
	line = open(sys.argv[1]).readline()
	RewriterTester(line)

	# for count, line in enumerate(open(sys.argv[1])):
	# 	if count == 100:
	# 		break
	# 	try:
	# 		OptimizerTester(line)
	# 	except Exception as e:
	# 		print(count, e)
	#
