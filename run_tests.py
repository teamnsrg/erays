from __future__ import print_function

from os import walk
import sys, signal

from datetime import datetime
from multiprocessing import Process, Manager, Lock

from aggregatortester import AggregatorTester
from optimizertester import OptimizerTester
from liftertester import LifterTester
from structurertester import StructurerTester


def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)


def worker(lock, file_path, exceptions, total, tester):
	file_name = file_path.split("/")[-1]
	eprint("start " + file_name)
	if file_name == "ak":
		print("fix this one later")
		return

	with open(file_path) as file:
		count = 0
		for count, line in enumerate(file):
			if count == 50:
				break
			# eprint(file_name, count)
			try:
				tester(line, False)
				signal.alarm(0)
			except Exception as ex:
				signal.alarm(0)
				transaction = "%s:%d" % (file_name, count)

				lock.acquire()
				exceptions[transaction] = (ex, len(line) / 1024)
				lock.release()
			# eprint(file_name, count)

	signal.alarm(0)
	lock.acquire()
	eprint("end %s %d" % (file_name, count))
	total.value += count
	lock.release()


def output_exception_report(path, exceptions, total):
	exception_report = open(path, "w")

	exception_report.write("total count %d\n" % total)
	exception_report.write("exception count %d\n" % len(exceptions))
	exception_report.write("=" * 20 + "\n")

	exception_types = dict()
	for ex, _ in exceptions.values():
		exception_type = type(ex).__name__
		if exception_type not in exception_types:
			exception_types[exception_type] = 0
		exception_types[exception_type] += 1

	for exception_type, c in exception_types.items():
		exception_report.write("%s : %d\n" % (exception_type, c))

	exception_report.write("=" * 20 + "\n")

	for count, (ex, code_size) in exceptions.items():
		exception_report.write("%s : %d [%s] %s\n" % (count, code_size, type(ex).__name__, str(ex)))
	exception_report.close()


if __name__ == '__main__':
	if "-l" in sys.argv:
		tester = LifterTester
	elif "-o" in sys.argv:
		tester = OptimizerTester
	elif "-a" in sys.argv:
		tester = AggregatorTester
	elif "-s" in sys.argv:
		tester = StructurerTester
	else:
		eprint("tester not specified")
		sys.exit()

	manager = Manager()
	exceptions = manager.dict()
	lock = Lock()
	total = manager.Value('total', 0)

	target_files = []
	for (path, _, file_names) in walk(sys.argv[-1]):
		for file_name in file_names:
			target_files.append(path + file_name)
		break

	processes = \
		[Process(target=worker, args=(lock, f, exceptions, total, tester)) for f in target_files]
	[process.start() for process in processes]

	[process.join() for process in processes]
	print("processes joined")
	file_path = "reports/" + tester.__name__ + datetime.now().strftime('_%m-%d-%H-%M')
	output_exception_report(file_path, exceptions, total.value)
