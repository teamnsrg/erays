from ceptions import JumpAddressError
from ceptions import StackSizeError
from bytecodes import *


def unfold_constant(bytecode):
	if isinstance(bytecode, PushByteCode):
		return bytecode.dependencies[0]
	elif isinstance(bytecode, BinOpByteCode):
		if bytecode.opcode == "AND":
			lhs = unfold_constant(bytecode.dependencies[0])
			rhs = unfold_constant(bytecode.dependencies[1])
			return lhs & rhs
	raise JumpAddressError("jump has no valid dependency")


class BasicResolver(object):
	def __init__(self, jump_dests):
		self.jump_dests = jump_dests
		self.__naturals = dict()

	def resolve_jump_target(self, bytecode):
		push_bytecode = bytecode.dependencies[0]
		pusher_id = push_bytecode.get_container_block_id()
		jump_address = unfold_constant(push_bytecode)  # should work
		if jump_address not in self.jump_dests:
			raise JumpAddressError("jump address %d is invalid" % jump_address)
		return self.jump_dests[jump_address], pusher_id, jump_address

	def get_natural_successor(self, block_id):
		if block_id in self.__naturals:
			return self.__naturals[block_id]
		return None

	def set_natural_successor(self, block_id, successor_id):
		self.__naturals[block_id] = successor_id

	def get_natural_successors(self):
		return self.__naturals


DUP_PLACE_HOLDER = -1


class DuplicateResolver:
	def __init__(self, basic_blocks, naturals):
		self.basic_blocks = basic_blocks
		self.duplicated = dict()
		self.jump_dests = set()
		self.__naturals = naturals

		self.head_addresses = dict()
		self.__allocate_id = 1000
		for block_id, basic_block in basic_blocks.items():
			entry_bytecode = basic_block.get_entry_bytecode()
			address = entry_bytecode.get_address()
			if entry_bytecode.is_jumpdest():
				self.jump_dests.add(address)
			self.head_addresses[address] = dict()
			self.head_addresses[address][DUP_PLACE_HOLDER] = block_id

	def resolve_jump_target(self, bytecode, stack_size):
		push_bytecode = bytecode.dependencies[0]
		jump_address = unfold_constant(push_bytecode)  # should work
		if jump_address not in self.jump_dests:
			raise JumpAddressError("jump address %d is invalid" % jump_address)
		return self.__resolve_address(jump_address, stack_size)

	# duplicates the block when stack size missing
	def __resolve_address(self, address, stack_size):
		candidates = self.head_addresses[address]
		original_id = candidates[DUP_PLACE_HOLDER]
		if stack_size not in candidates:
			if len(candidates) == 1:
				candidates[stack_size] = original_id
				return original_id
			else:
				basic_block = self.basic_blocks[original_id]
				# print(original_id, self.allocate_id)
				dup_block = basic_block.make_copy(self.allocate_id())
				dup_id = dup_block.get_id()
				self.basic_blocks[dup_id] = dup_block
				self.duplicated[dup_id] = original_id

				# print("duped %s -> %s" % (original_id, dup_id))
				candidates[stack_size] = dup_block.get_id()
		return candidates[stack_size]

	def resolve_natural_successor(self, block_id, stack_size):
		original_id = block_id
		if block_id in self.duplicated:
			original_id = self.duplicated[block_id]

		if original_id not in self.__naturals:
			return None

		suc_id = self.__naturals[original_id]
		if suc_id is None:
			return None

		basic_block = self.basic_blocks[suc_id]
		entry_bytecode = basic_block.get_entry_bytecode()
		address = entry_bytecode.get_address()
		# might need to duplicate the successor
		new_suc_id = self.__resolve_address(address, stack_size)

		# self.__naturals[block_id] = new_suc_id
		return new_suc_id

	def allocate_id(self):
		self.__allocate_id += 1
		return self.__allocate_id

	# lookup only
	def lookup_address(self, address, stack_size):
		if address not in self.jump_dests:
			return None
		candidates = self.head_addresses[address]
		if stack_size not in candidates:
			raise StackSizeError("stack size not found")
		return candidates[stack_size]

	# def lookup_natural(self, block_id):
	# 	if block_id not in self.__naturals:
	# 		return None
	# 	return self.__naturals[block_id]
