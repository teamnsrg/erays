from bytecodeblock import *

from copy import deepcopy
from operator import attrgetter


DUMMY_BLOCK_ID = -42


class ControlGraph(object):
	def __init__(self):
		self.basic_blocks = dict()
		self.outgoing_edges = dict()
		self.incoming_edges = dict()

		self.dominators = dict()
		self.post_dominators = dict()

		self.__indirect_jumps = set()

		self.marked_block_ids = dict()
		self.entry_block_ids = set()

		self.__allocate_id = 2000  # whatever, I give up

	def size(self):
		return len(self.basic_blocks)

	def mark_entry_block(self, block_id):
		if block_id in self.basic_blocks:
			self.entry_block_ids.add(block_id)

	def replace_block(self, basic_block):
		str_id = basic_block.get_id()
		if str_id not in self.basic_blocks:
			print("[WARNING] nothing to replace")
			return
		self.basic_blocks[str_id] = basic_block

	def add_block(self, block):
		cur_id = block.get_id()
		if cur_id in self.basic_blocks:
			return
		self.basic_blocks[cur_id] = block
		self.outgoing_edges[cur_id] = set()
		self.incoming_edges[cur_id] = set()

	def remove_block(self, block_id):
		if block_id in self.basic_blocks:
			del(self.basic_blocks[block_id])
		if block_id in self.dominators:
			del(self.dominators[block_id])
		if block_id in self.post_dominators:
			del(self.post_dominators[block_id])

		successor_ids = list()
		if block_id in self.outgoing_edges:
			successor_ids = self.outgoing_edges[block_id]
			del(self.outgoing_edges[block_id])
		for successor_id in successor_ids:
			incoming_paths = self.incoming_edges[successor_id]
			incoming_paths.remove(block_id)

		predecessor_ids = list()
		if block_id in self.incoming_edges:
			predecessor_ids = self.incoming_edges[block_id]
			del(self.incoming_edges[block_id])
		for predecessor_id in predecessor_ids:
			outgoing_paths = self.outgoing_edges[predecessor_id]
			outgoing_paths.remove(block_id)

	def remove_blocks(self, block_ids):
		for block_id in block_ids:
			self.remove_block(block_id)

	def has_block(self, block_id):
		return block_id in self.basic_blocks

	def has_blocks(self, str_ids):
		for cur_id in str_ids:
			if cur_id not in self.basic_blocks:
				return False
		return True

	def add_edge(self, src_id, dst_id, indirect=False):
		if src_id not in self.basic_blocks \
			or dst_id not in self.basic_blocks:
			return
		self.outgoing_edges[src_id].add(dst_id)
		self.incoming_edges[dst_id].add(src_id)
		if indirect:
			self.__indirect_jumps.add((src_id, dst_id))

	def remove_edge(self, src_id, dst_id=-101):
		if dst_id == -101:
			outgoing_paths = self.outgoing_edges[src_id]
			self.outgoing_edges[src_id] = set()
			for dst_id in outgoing_paths:
				self.incoming_edges[dst_id].remove(src_id)
			return
		try:
			self.outgoing_edges[src_id].remove(dst_id)
			self.incoming_edges[dst_id].remove(src_id)
		except KeyError:
			# print("[DEBUG]: %d -> %d does not exist" % (src_id, dst_id))
			pass

	def has_edge(self, src_id, dst_id):
		return src_id in self.outgoing_edges \
			and dst_id in self.outgoing_edges[src_id]

	def get_single_predecessor(self, block_id):
		pre_ids = self.get_predecessor_ids(block_id)
		if len(pre_ids) == 1 and block_id not in pre_ids:
			return pre_ids.pop()

	def get_single_successor(self, block_id):
		suc_ids = self.get_successor_ids(block_id)
		if len(suc_ids) == 1 and block_id not in suc_ids:
			return suc_ids.pop()

	def get_dual_successors(self, block_id):
		suc_ids = self.get_successor_ids(block_id)
		if len(suc_ids) == 2 and block_id not in suc_ids:
			return suc_ids

		# def validate_path_exists(self, path):
	# 	parent_id = path[0]
	# 	for block_id in path[1:]:
	# 		# if parent_id not in self.outgoing_paths:
	# 			# raise TraceError("there is no path %d -> %d" % (parent_id, block_id))
	# 		if block_id not in self.outgoing_edges[parent_id]:
	# 			raise GraphValidationError("there is no path %s -> %s" % (parent_id, block_id))
	# 		parent_id = block_id
	# 	return True

	def get_blocks(self):
		return self.basic_blocks

	def get_block(self, block_id):
		if block_id not in self.basic_blocks:
			return None
		return self.basic_blocks[block_id]

	def get_block_ids(self):
		return sorted(self.basic_blocks.keys())

	def get_successor_ids(self, block_id):
		if block_id in self.outgoing_edges:
			return set(self.outgoing_edges[block_id])
		return set()

	def get_natural_successor(self, block_id):
		suc_ids = self.get_successor_ids(block_id)
		if len(suc_ids) == 0:
			return None
		cur_block = self[block_id]
		ext_addr = cur_block.get_exit_address()
		natural = \
			min(suc_ids, key=lambda x: abs(self[x].get_entry_address() - ext_addr))
		return natural

	def get_predecessor_ids(self, block_id):
		if block_id in self.incoming_edges:
			return set(self.incoming_edges[block_id])
		return set()

	def get_subgraph(self, block_ids):
		subgraph = ControlGraph()
		if not block_ids:
			return subgraph

		for block_id in block_ids:
			if block_id not in self.basic_blocks:
				continue
			basic_block = self.basic_blocks[block_id]
			subgraph.add_block(basic_block)
		for block_id in block_ids:
			if block_id not in self.outgoing_edges:
				continue
			for dst_id in self.outgoing_edges[block_id]:
				subgraph.add_edge(block_id, dst_id)

		for block_id, color in self.marked_block_ids.items():
			subgraph.mark_basic_block(block_id, color)

		subgraph.__indirect_jumps = deepcopy(self.__indirect_jumps)
		return subgraph

	def get_path(self, src_id, dst_id):
		path = self.__get_path(src_id, dst_id, set())
		if path is not None:
			path.reverse()
		return path

	def __get_path(self, src_id, dst_id, visited):
		if src_id == dst_id:
			return [dst_id]
		if src_id in visited:
			return None
		visited.add(src_id)

		successor_ids = self.get_successor_ids(src_id)
		for successor_id in successor_ids:
			path = self.__get_path(successor_id, dst_id, visited)
			if path is None:
				continue
			path.append(src_id)
			return path
		return None

	def create_dominance_relation(self, entry_id):
		dummy_block = BytecodeBlock(DUMMY_BLOCK_ID)
		dummy_str_id = dummy_block.get_id()
		self.add_block(dummy_block)
		block_ids = set(self.get_block_ids())

		for block_id in block_ids:
			self.dominators[block_id] = deepcopy(block_ids)
		self.dominators[dummy_str_id] = {dummy_str_id}
		self.add_edge(dummy_str_id, entry_id)
		changed = True
		while changed:
			changed = False
			for block_id_1 in block_ids:
				predecessor_ids = self.get_predecessor_ids(block_id_1)
				if len(predecessor_ids) == 0:
					continue
				intersection_ids = deepcopy(block_ids)
				for block_id_2 in predecessor_ids:
					intersection_ids = intersection_ids.intersection(self.dominators[block_id_2])
				intersection_ids.add(block_id_1)
				if self.dominators[block_id_1] != intersection_ids:
					changed = True
				self.dominators[block_id_1] = intersection_ids

		for block_id, dominators in self.dominators.items():
			dominators.remove(dummy_str_id)
		self.remove_block(dummy_str_id)

	def get_dominance_frontiers(self, entry_id):
		self.create_dominance_relation(entry_id)
		dominates_over = dict()
		for cur_id, dominator_ids in self.dominators.items():
			for dom_id in dominator_ids:
				if dom_id not in dominates_over:
					dominates_over[dom_id] = set()
				dominates_over[dom_id].add(cur_id)
		dominance_frontiers = dict()
		for cur_id in self.get_block_ids():
			dominance_frontiers[cur_id] = set()
		for cur_id, pre_ids in dominates_over.items():
			dominance_frontier = set()
			for pre_id in pre_ids:
				dominance_frontier |= self.get_successor_ids(pre_id)
			dominance_frontier -= (set(pre_ids) - {cur_id})
			dominance_frontiers[cur_id] = dominance_frontier
		return dominance_frontiers

	def get_dominator_tree(self, entry_id):
		self.create_dominance_relation(entry_id)
		dominator_tree = dict()
		for cur_id in self.get_block_ids():
			imm_dominator = self.__get_immediate_dominator(cur_id)
			if imm_dominator not in dominator_tree:
				dominator_tree[imm_dominator] = set()
			dominator_tree[imm_dominator].add(cur_id)
		return dominator_tree

	def __get_immediate_dominator(self, cur_id):
		strict_dominators = set(self.dominators[cur_id]) - {cur_id}
		imm_dominator = None
		while len(strict_dominators) != 0:
			imm_dominator = strict_dominators.pop()
			found = True  # find the closest dominator
			for i in strict_dominators:
				if self.dominates_over(imm_dominator, i):
					found = False
			if found:
				break
		if not imm_dominator:
			return
		strict_dominators = set(self.dominators[imm_dominator]) - {imm_dominator}
		for s in strict_dominators:
			assert(self.dominates_over(s, cur_id))
		return imm_dominator

	def dominates_over(self, src_id, dst_id):
		return src_id in self.dominators[dst_id]

	def create_post_dominance_relation(self):
		exit_ids = set()
		for block_id, successor_ids in self.outgoing_edges.items():
			if len(successor_ids) == 0:
				exit_ids.add(block_id)

		fake_exit = BytecodeBlock(-42)
		self.add_block(fake_exit)
		for exit_id in exit_ids:
			self.add_edge(exit_id, -42)

		block_ids = set(self.get_block_ids())
		for block_id in block_ids:
			self.post_dominators[block_id] = deepcopy(block_ids)
		self.post_dominators[-42] = {-42}
		changed = True
		while changed:
			changed = False
			for block_id_1 in block_ids:
				predecessor_ids = self.get_successor_ids(block_id_1)
				if len(predecessor_ids) == 0:
					continue
				intersection_ids = deepcopy(block_ids)
				for block_id_2 in predecessor_ids:
					intersection_ids = intersection_ids.intersection(self.post_dominators[block_id_2])
				intersection_ids.add(block_id_1)
				if self.post_dominators[block_id_1] != intersection_ids:
					changed = True
				self.post_dominators[block_id_1] = intersection_ids

		for block_id in self.post_dominators:
			self.post_dominators[block_id].remove(-42)
		self.remove_block(-42)

	def post_dominates_over(self, src_id, dst_id):
		return src_id in self.post_dominators[dst_id]

	def depth_first_search(self, entry_id):
		order = list()
		self.__depth_first_search(entry_id, set(), order)
		return order

	def __depth_first_search(self, block_id, visited, order):
		if block_id in visited:
			return
		visited.add(block_id)
		for successor_id in self.get_successor_ids(block_id):
			self.__depth_first_search(successor_id, visited, order)
		order.append(block_id)

	# def get_topological_ordering(self, entry_id):
	# 	sorted_block_ids = list()
	# 	orphan_block_ids = {entry_id}
	# 	incoming_paths = deepcopy(self.incoming_edges)
	# 	removed_block_ids = set()
	# 	for block_id, predecessor_ids in incoming_paths.items():
	# 		predecessor_ids = list(predecessor_ids)
	# 		for predecessor_id in predecessor_ids:
	# 			if self.dominates_over(block_id, predecessor_id):
	# 				incoming_paths[block_id].remove(predecessor_id)
	#
	# 	while len(orphan_block_ids):
	# 		block_id = orphan_block_ids.pop()
	# 		sorted_block_ids.append(block_id)
	# 		removed_block_ids.add(block_id)
	# 		for successor_id in self.get_successor_ids(block_id):
	# 			if self.dominates_over(successor_id, block_id):
	# 				# ignore back edge
	# 				continue
	# 			successor_ids = incoming_paths[successor_id]
	# 			successor_ids.remove(block_id)
	# 			if len(successor_ids) == 0:
	# 				orphan_block_ids.add(successor_id)
	# 	for _, predecessor_ids in incoming_paths.items():
	# 		assert (len(predecessor_ids) == 0)
	# 	return sorted_block_ids
	# def __reverse_depth_first_search(self, block_id, visited):
	# 	visited.add(block_id)
	# 	predecessor_ids = self.get_predecessor_ids(block_id)
	# 	for block_id in predecessor_ids:
	# 		self.__reverse_depth_first_search(block_id, visited)

	# def get_strongly_connected_components(self, entry_id=0):
	# 	stack = list()
	# 	self.depth_first_search(entry_id, set(), stack)
	#
	# 	connected_components = list()
	# 	for block_id in reversed(stack):
	# 		visited = set()
	# 		self.__reverse_depth_first_search(block_id, visited)
	#
	# 		if len(visited) > 1:
	# 			connected_components.append(visited)
	# 	return connected_components

	def get_subgraph_entry_ids(self, block_ids):
		entry_ids = dict()
		for block_id in block_ids:
			predecessor_ids = self.get_predecessor_ids(block_id)
			for predecessor_id in predecessor_ids:
				if predecessor_id not in block_ids:
					if block_id not in entry_ids:
						entry_ids[block_id] = {predecessor_id}
					else:
						entry_ids[block_id].add(predecessor_id)
		return entry_ids

	def get_subgraph_exit_ids(self, block_ids):
		exit_ids = dict()
		for block_id in block_ids:
			successor_ids = self.get_successor_ids(block_id)
			for successor_id in successor_ids:
				if successor_id not in block_ids:
					if block_id not in exit_ids:
						exit_ids[block_id] = {successor_id}
					else:
						exit_ids[block_id].add(successor_id)
		return exit_ids

	def mark_basic_block(self, block_id, color):
		if block_id not in self.basic_blocks:
			return
		self.marked_block_ids[block_id] = color

	def get_bytecode_count(self, opcode):
		count = 0
		for basic_block in self:
			for bytecode in basic_block:
				if bytecode.opcode == opcode:
					count += 1
					break
		return count

	def get_back_edge_count(self, entry_id):
		count = 0
		self.create_dominance_relation(entry_id)
		# print(self.dominators)
		for block_id in self.outgoing_edges:
			for successor_id in self.outgoing_edges[block_id]:
				if self.dominates_over(successor_id, block_id):
					count += 1
		return count

	def transfer_predecessors(self, block_id, new_id):
		# print(block_id, new_id)
		for pre_id in self.get_predecessor_ids(block_id):
			self.remove_edge(pre_id, block_id)
			self.add_edge(pre_id, new_id)

	def transfer_successors(self, block_id, new_id):
		for suc_id in self.get_successor_ids(block_id):
			self.remove_edge(block_id, suc_id)
			self.add_edge(new_id, suc_id)

	def get_complexity(self):
		branch_count = 0
		exit_count = 0
		for basic_block in self.basic_blocks.values():
			if basic_block.is_exit_block():
				exit_count += 1
			elif basic_block.is_jumpi_block():
				branch_count += 1
		return branch_count - exit_count + 2

	def allocate_id(self):
		self.__allocate_id += 1
		return self.__allocate_id

	def visualize(self, file_name, interal=None):
		dot_file = open(file_name, 'w')
		dot_file.write("digraph {\nnode [shape=rect,fontname=\"Courier\"];\n")
		if interal:
			dot_file.write("labelloc=\"t\";\nfontname=\"Courier\"\n")
			r, w = interal
			r = "args " + " ".join(r) + "\l"
			w = "rets " + " ".join(w) + "\l"

			dot_file.write("label=\"%s\l%s\";\n" % (r, w))

		for cur_id in self.basic_blocks:
			# if cur_id in self.marked_block_ids:
			# 	color = self.marked_block_ids[cur_id]
			# 	dot_file.write("%d [style=filled, fillcolor=%s]\n" % (cur_id, color))
			# else:
			block = self.basic_blocks[cur_id]
			label = block.dot_format_block(0).lower()

			label = hex(block.get_entry_address()) + "\l--------\l" + label
			# print(label.lower())
			dot_file.write(str(cur_id) + "[label=\"%s\"];\n" % label)
			suc_ids = self.get_successor_ids(cur_id)
			for suc_id in suc_ids:
				if (cur_id, suc_id) not in self.__indirect_jumps:
					line = "%d -> %d\n" % (cur_id, suc_id)
				else:
					line = "%d -> %d[color=red]\n" % (cur_id, suc_id)
				dot_file.write(line)
		dot_file.write("}\n")
		dot_file.close()

	def simplify(self, skip_blocks, resolver=None):
		merged = dict()
		change = True
		while change:
			removed = set()
			for block_id, block in self.get_blocks().items():
				if block_id in removed:
					continue
				suc_id = self.__can_merge(block_id)
				if suc_id is None or block_id in skip_blocks:
					continue
				suc_block = self[suc_id]
				block.merge(suc_block)

				self.remove_edge(block_id, suc_id)
				suc_ids = self.get_successor_ids(suc_id)
				for i in suc_ids:
					self.add_edge(block_id, i)

				self.remove_block(suc_id)
				removed.add(suc_id)
				merged[suc_id] = block_id

				if resolver is not None:
					nas = resolver.get_natural_successor(suc_id)  # don't care if none
					resolver.set_natural_successor(block_id, nas)
			change = len(removed) != 0
		return merged

	def __can_merge(self, block_id):
		suc_ids = self.get_successor_ids(block_id)
		if len(suc_ids) != 1:
			return None
		suc_id = suc_ids.pop()
		if len(self.get_predecessor_ids(suc_id)) != 1:
			return None
		suc_ids = self.get_successor_ids(suc_id)
		if suc_id in suc_ids or block_id in suc_ids:
			return None
		return suc_id

	def __iter__(self):
		block_ids = sorted(self.basic_blocks.keys())
		for block_id in block_ids:
			yield self.basic_blocks[block_id]

	def __getitem__(self, block_id):
		return self.basic_blocks[block_id]