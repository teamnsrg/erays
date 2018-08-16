from baseexecutor import INTRETURN_ADDRESS
from expressionblock import ExpressionBlock
from expressionexecutor import ExpressionExecutor
from structures import *


class StructureExecutor(ExpressionExecutor):
	def __init__(self, reader, lifter, debug):
		ExpressionExecutor.__init__(self, reader, lifter, debug)

	def execute_function(self, func):
		cur_id = func.entry_id
		count = 0
		while cur_id is not None:
			# if self.debug:
			# 	print("block_%s" % cur_id)
				# self.memory.debug_memory()
			address = self.execute_structure(func.graph[cur_id])

			if address == INTRETURN_ADDRESS:
				return  # return from recursive call

			if address is None:
				cur_id = func.graph.get_natural_successor(cur_id)
			else:
				cur_id = self.get_jump_successor(func.graph, cur_id, address)
			count += 1

	def execute_structure(self, block):
		if isinstance(block, ExpressionBlock):
			return self.execute_block(block)
		elif isinstance(block, Seq):
			return self.execute_seq(block)
		elif isinstance(block, IfThen):
			return self.execute_ifthen(block)
		elif isinstance(block, IfThenElse):
			return self.execute_ifthenelse(block)
		elif isinstance(block, Loop):
			return self.execute_loop(block)

		print(block)
		assert False

	def execute_seq(self, structure):
		blocks = structure.get_blocks()
		address = None
		for block in blocks:
			address = self.execute_structure(block)
		return address

	def execute_ifthen(self, structure):
		a0 = structure.get_nth_block(0)
		address = self.execute_block(a0)
		if address is None:
			a1 = structure.get_nth_block(1)
			self.execute_structure(a1)

	def execute_ifthenelse(self, structure):
		a0 = structure.get_nth_block(0)
		address = self.execute_block(a0)
		if address is None:
			a1 = structure.get_nth_block(1)
			self.execute_structure(a1)
		else:
			a2 = structure.get_nth_block(2)
			self.execute_structure(a2)

	def execute_loop(self, structure):
		a0 = structure.get_nth_block(0)
		a1 = structure.get_nth_block(1)
		assert isinstance(a0, Seq) or isinstance(a0, ExpressionBlock)

		while True:
			address = self.execute_structure(a0)
			if address is not None:
				break
			self.execute_structure(a1)
