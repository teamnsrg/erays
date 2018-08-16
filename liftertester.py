from instructionexecutor import InstructionExecutor
from lifter import Lifter
from tracereader import TraceReader, EffectReader
from ceptions import TimeoutException

import signal, sys


def handler(signum, frame):
	raise TimeoutException("timeout")


class LifterTester:
	def __init__(self, line, debug):
		reader = EffectReader(line)
		reader.parse_trace()

		signal.signal(signal.SIGALRM, handler)
		signal.alarm(15)
		lifter = Lifter(reader.code)
		InstructionExecutor(reader, lifter, debug)
		signal.alarm(0)


if __name__ == "__main__":
	debug = "-d" in sys.argv
	line = open(sys.argv[1]).readline()
	LifterTester(line, debug)
