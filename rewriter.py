# from optimizer import Optimizer
# from blockstate import MemState
# from instructions import SHA3Operation, MoveInstruction
#
# from opcodes import log_ops
#
# import sys
#
#
# def rewrite_sha3_operation(block):
# 	local_memory = MemState()
# 	instructions = block.get_instructions()
# 	changed = False
# 	for index, instruction in enumerate(instructions):
# 		if instruction.opcode == "SHA3":
# 			begin, end = instruction.reads
# 			if begin == 0 and not isinstance(end, str):
# 				addresses = range(begin, end, 32)
# 				items = local_memory.lookup_mapping(addresses)
# 				if len(items) != 0:
# 					changed = True
# 					values, indices = zip(*items)
# 					for i in indices:
# 						block.set_nop_instruction(i)
# 					operation = SHA3Operation(values, instruction.writes, instruction.address)
# 					block.set_instruction(index, operation)
# 		# local_memory.debug_state()
# 		# print(instruction)
# 		local_memory.add_mapping(index, instruction)
# 	# block.debug_block()
# 	return changed
#
#
# # def rewrite_log_operation(block):
# # 	instructions = block.get_instructions()
# # 	print(block.get_str_id())
# # 	for index, instruction in enumerate(instructions):
# # 		# if instruction.opcode in log_ops:
# # 		print(str(instruction).lower())
# # 	print("")
#
# # def rewrite_free_ptr(block):
# # 	for i, instruction in enumerate(block.get_instructions()):
# # 		if instruction.opcode == "MLOAD" and \
# # 			instruction.reads[0] == 64:
# # 			new_instruction = MoveInstruction("MOVE", ["$m"], instruction.writes, instruction.address)
# # 			block.set_instruction(i, new_instruction)
# # 		elif instruction.opcode == "MSTORE" and \
# # 			instruction.reads[0] == 64:
# # 			new_instruction = MoveInstruction("MOVE", [instruction.reads[1]], ["$m"], instruction.address)
# # 			block.set_instruction(i, new_instruction)
#
#
# def remove_nops(block):
# 	new_instructions = list()
# 	for instruction in block:
# 		if instruction.opcode != "NOP":
# 			new_instructions.append(instruction)
# 	block.set_instructions(new_instructions)
#
#
# class Rewriter(Optimizer):
# 	def __init__(self, binary):
# 		Optimizer.__init__(self, binary)
# 		for func in self.get_all_functions():
# 			self.__rewrite_function(func)
#
# 	def __rewrite_function(self, func):
# 		for block in func.graph.get_basic_blocks():
# 			self.__rewrite_instruction_block(block)
# 			# self.__rewrite_assert_operation(func, block)
# 			pass
#
# 	# @staticmethod
# 	# def __rewrite_assert_operation(func, block):
# 	# 	graph = func.graph
# 	# 	block_id = block.get_str_id()
# 	# 	suc_ids = graph.get_successor_ids(block_id)
# 	# 	if len(suc_ids) != 2 or not block.is_condition_block():
# 	# 		return
# 	# 	suc_id_0, suc_id_1 = suc_ids
# 	# 	suc_0, suc_1 = graph[suc_id_0], graph[suc_id_1]
# 	# 	if suc_1.is_abort_block():
# 	# 		suc_id_0, suc_id_1 = suc_id_1, suc_id_0
# 	# 		suc_0, suc_1 = suc_1, suc_0
# 	# 	if not suc_0.is_abort_block() or \
# 	# 		len(graph.get_predecessor_ids(suc_id_1)) != 1:
# 	# 		return
# 	#
# 	# 	block.insert_assert_operation()
# 	# 	graph.remove_block(suc_id_0)
#
# 	@staticmethod
# 	def __rewrite_instruction_block(block):
# 		rewrite_sha3_operation(block)
# 		remove_nops(block)
# 		# rewrite_free_ptr(block)
# 		# rewrite_log_operation(block)
#
# 		# for instruction in block:
#
#
# if __name__ == "__main__":
# 	input_file = open(sys.argv[1])
# 	line = input_file.readline().strip()
# 	if " " in line:
# 		line = line.split(" ")[1]
# 	input_file.close()
# 	a = Rewriter(line)
# 	a.debug_functions()
