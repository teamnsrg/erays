from structurer import Structurer
from structureexecutor import StructureExecutor
from tracereader import EffectReader
from ceptions import TimeoutException

import signal, sys


def handler(signum, frame):
	raise TimeoutException("timeout")


class StructurerTester:
	def __init__(self, line, debug):
		reader = EffectReader(line)
		# reader = TraceReader(line)
		reader.parse_trace()
		self.code_size = len(reader.code)

		signal.signal(signal.SIGALRM, handler)
		signal.alarm(15)
		# print(reader.signature)
		analyzer = Structurer(reader.code)
		StructureExecutor(reader, analyzer, debug)
		signal.alarm(0)

	def get_code_size(self):
		return self.code_size


if __name__ == "__main__":
	line = open(sys.argv[1]).readline()
	StructurerTester(line, True)

