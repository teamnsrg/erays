import sys, json

line = open(sys.argv[1]).readline()
info = json.loads(line)
trace = info['result']['structLogs']

for step in trace:
	if step['depth'] != 1:
		continue
	for i, item in enumerate(step['stack']):
		print("$s%d:\t%s" % (i, hex(int(item, 16))[2:]))
	for i in step['memory']:
		print(i)
	# print("".join(step['memory']))
	print("-" * 32)
	print(str(step['pc']) + "\t" + step['op'])
	print("-" * 32)
