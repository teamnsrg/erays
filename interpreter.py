from controlgraph import *
from ceptions import DependencyError
from ceptions import JumpAddressError
from image import Image
from imagetracker import ImageTracker
from resolver import DuplicateResolver
from opcodes import *


class Interpreter(object):
	def __init__(self, basic_blocks, resolver):
		self.basic_blocks = basic_blocks
		self.resolver = resolver
		self._poison_ids = set()

	def add_to_poison(self, cur_id):
		self._poison_ids.add(cur_id)

	@staticmethod
	def _resolve_data_dependency(cur_block, pre_tracker):
		# another copy is necessary here
		image = Image(cur_block.get_id(), pre_tracker)
		for bytecode in cur_block:
			# I actually don't know if this is right
			bytecode.reset_dependencies()
			try:
				image.interpret_bytecode(bytecode)
			except KeyError:
				raise DependencyError("cannot resolve byte code read dependency")
		return image


class BasicInterpreter(Interpreter):
	def __init__(self, basic_blocks, resolver):
		Interpreter.__init__(self, basic_blocks, resolver)
		self.__image_trackers = None
		self.__graph = ControlGraph()
		self.ambiguous_blocks = dict()
		self.__end_paths = list()
		self.__max_path_len = len(basic_blocks)

	def explore_control_flow_graph(self, cur_id, tracker):
		# print(cur_id, tracker)
		self.__image_trackers = ImageTracker()

		self.__graph.add_block(self.basic_blocks[cur_id])
		self.__create_execution_path(cur_id, tracker, [])
		return self.__graph, self.__image_trackers

	def __create_execution_path(self, cur_id, pre_tracker, path):
		if self.__image_trackers.mark_observed_image(cur_id, pre_tracker):
			return

		if len(path) > self.__max_path_len:
			return

		if cur_id in self._poison_ids:
			self.__end_paths.append(path)
			return

		cur_block = self.basic_blocks[cur_id]
		tracker = Interpreter._resolve_data_dependency(cur_block, pre_tracker)
		cpy_tracker = tracker.make_copy()

		exit_instruction = cur_block.get_exit_bytecode()
		opcode = exit_instruction.opcode

		if opcode in jump_ops:
			self.__create_jump_execution_path(cur_block, tracker, path)

		if opcode not in exit_ops and opcode not in {"JUMP", "ASSERT"}:
			self.__create_natural_execution_path(cur_block, cpy_tracker, path)

	def __create_jump_execution_path(self, cur_block, tracker, path):
		exit_instruction = cur_block.get_exit_bytecode()
		cur_id = cur_block.get_id()
		try:
			suc_id, push_id, jump_address = self.resolver.resolve_jump_target(exit_instruction)
		except JumpAddressError:
			return
		suc_block = self.basic_blocks[suc_id]
		self.__graph.add_block(suc_block)
		self.__graph.add_edge(cur_id, suc_id, cur_id != push_id)
		self.__add_to_ambiguous_blocks(cur_id, suc_id, push_id)
		self.__create_execution_path(suc_id, tracker, path + [cur_id])

	def __add_to_ambiguous_blocks(self, cur_id, suc_id, push_id):
		if push_id == cur_id:
			return
		if cur_id not in self.ambiguous_blocks:
			self.ambiguous_blocks[cur_id] = dict()
		self.ambiguous_blocks[cur_id][push_id] = suc_id

	def __create_natural_execution_path(self, cur_block, tracker, path):
		suc_id = self.resolver.get_natural_successor(cur_block.get_id())
		if suc_id is None:
			return
		suc_block = self.basic_blocks[suc_id]
		# self.non_ambiguous_jumps[cur_block.get_id()] = suc_block.get_entry_address()
		self.__graph.add_block(suc_block)
		self.__graph.add_edge(cur_block.get_id(), suc_id)
		# print(type(suc_id))
		self.__create_execution_path(suc_id, tracker, path + [cur_block.get_id()])

	def get_end_path(self):
		return self.__end_paths[0]

	def compute_stack_actions(self, str_ids):
		total_delta, stack_size = 0, 0
		for str_id in str_ids:
			basic_block = self.basic_blocks[str_id]
			for byte_code in basic_block:
				opcode = byte_code.opcode
				delta = actions[opcode][0]
				alpha = actions[opcode][1]
				stack_size -= delta
				total_delta = min(total_delta, stack_size)
				stack_size += alpha
		total_alpha = stack_size - total_delta
		# print(-total_delta, total_alpha, stack_size)
		return -total_delta, total_alpha


class DuplicateInterpreter(Interpreter):
	def __init__(self, basic_blocks, naturals):
		Interpreter.__init__(self, basic_blocks, None)
		self.resolver = DuplicateResolver(basic_blocks, naturals)
		self.__graph = None
		self.__image_trackers = None
		self.ins_outs = dict()

	def explore_control_flow_graph(self, cur_id, image):
		self.__graph = ControlGraph()
		self.__image_trackers = ImageTracker()
		if image is None:
			image = Image(1)

		self.__graph.add_block(self.basic_blocks[cur_id])
		self.__create_execution_path(cur_id, image, [])
		return self.__graph, self.__image_trackers

	def __create_execution_path(self, cur_id, pre_image, path):
		if self.__image_trackers.mark_observed_image(cur_id, pre_image):
			return

		if cur_id in self._poison_ids:
			return

		cur_block = self.basic_blocks[cur_id]
		image = Interpreter._resolve_data_dependency(cur_block, pre_image)
		cpy_image = image.make_copy()

		exit_instruction = cur_block.get_exit_bytecode()
		opcode = exit_instruction.opcode

		if opcode in jump_ops:
			self.__create_jump_execution_path(pre_image.block_id, cur_block, image, path)

		if opcode not in exit_ops and opcode != "JUMP":
			self.__create_natural_execution_path(cur_block, cpy_image, path)

	def __create_jump_execution_path(self, pre_id, cur_block, image, path):
		exit_instruction = cur_block.get_exit_bytecode()
		cur_id = cur_block.get_id()
		try:
			suc_id = self.resolver.resolve_jump_target(exit_instruction, image.top)
		except JumpAddressError:
			return

		if cur_id not in self.ins_outs:
			self.ins_outs[cur_id] = dict()
		mmp = self.ins_outs[cur_id]
		if pre_id not in mmp:
			mmp[pre_id] = set()
		mmp[pre_id].add(suc_id)

		suc_block = self.basic_blocks[suc_id]
		self.__graph.add_block(suc_block)
		self.__graph.add_edge(cur_id, suc_id)
		self.__create_execution_path(suc_id, image, path + [cur_id])

	def __create_natural_execution_path(self, cur_block, image, path):
		suc_id = self.resolver.resolve_natural_successor(cur_block.get_id(), image.top)
		if not suc_id:
			return
		suc_block = self.basic_blocks[suc_id]
		self.__graph.add_block(suc_block)
		self.__graph.add_edge(cur_block.get_id(), suc_id)
		self.__create_execution_path(suc_id, image, path + [cur_block.get_id()])
