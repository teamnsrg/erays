opcodes = {
	0x00: "STOP",
	0x01: "ADD",
	0x02: "MUL",
	0x03: "SUB",
	0x04: "DIV",
	0x05: "SDIV",
	0x06: "MOD",
	0x07: "SMOD",
	0x08: "ADDMOD",
	0x09: "MULMOD",
	0x0a: "EXP",
	0x0b: "SIGNEXTEND",
	0x10: "LT",
	0x11: "GT",
	0x12: "SLT",
	0x13: "SGT",
	0x14: "EQ",
	0x15: "ISZERO",
	0x16: "AND",
	0x17: "OR",
	0x18: "XOR",
	0x19: "NOT",
	0x1a: "BYTE",

	0x20: "SHA3",
	0x21: "NONZERO",

	0x30: "ADDRESS",
	0x31: "BALANCE",
	0x32: "ORIGIN",
	0x33: "CALLER",
	0x34: "CALLVALUE",
	0x35: "CALLDATALOAD",
	0x36: "CALLDATASIZE",
	0x37: "CALLDATACOPY",
	0x38: "CODESIZE",
	0x39: "CODECOPY",
	0x3a: "GASPRICE",
	0x3b: "EXTCODESIZE",
	0x3c: "EXTCODECOPY",

	0x40: "BLOCKHASH",
	0x41: "COINBASE",
	0x42: "TIMESTAMP",
	0x43: "NUMBER",
	0x44: "DIFFICULTY",
	0x45: "GASLIMIT",

	0x50: "POP",
	0x51: "MLOAD",
	0x52: "MSTORE",
	0x53: "MSTORE8",
	0x54: "SLOAD",
	0x55: "SSTORE",
	0x56: "JUMP",
	0x57: "JUMPI",
	0x58: "PC",
	0x59: "MSIZE",
	0x5a: "GAS",
	0x5b: "JUMPDEST",

	0x60: "PUSH1",
	0x61: "PUSH2",
	0x62: "PUSH3",
	0x63: "PUSH4",
	0x64: "PUSH5",
	0x65: "PUSH6",
	0x66: "PUSH7",
	0x67: "PUSH8",
	0x68: "PUSH9",
	0x69: "PUSH10",
	0x6a: "PUSH11",
	0x6b: "PUSH12",
	0x6c: "PUSH13",
	0x6d: "PUSH14",
	0x6e: "PUSH15",
	0x6f: "PUSH16",
	0x70: "PUSH17",
	0x71: "PUSH18",
	0x72: "PUSH19",
	0x73: "PUSH20",
	0x74: "PUSH21",
	0x75: "PUSH22",
	0x76: "PUSH23",
	0x77: "PUSH24",
	0x78: "PUSH25",
	0x79: "PUSH26",
	0x7a: "PUSH27",
	0x7b: "PUSH28",
	0x7c: "PUSH29",
	0x7d: "PUSH30",
	0x7e: "PUSH31",
	0x7f: "PUSH32",

	0x80: "DUP1",
	0x81: "DUP2",
	0x82: "DUP3",
	0x83: "DUP4",
	0x84: "DUP5",
	0x85: "DUP6",
	0x86: "DUP7",
	0x87: "DUP8",
	0x88: "DUP9",
	0x89: "DUP10",
	0x8a: "DUP11",
	0x8b: "DUP12",
	0x8c: "DUP13",
	0x8d: "DUP14",
	0x8e: "DUP15",
	0x8f: "DUP16",

	0x90: "SWAP1",
	0x91: "SWAP2",
	0x92: "SWAP3",
	0x93: "SWAP4",
	0x94: "SWAP5",
	0x95: "SWAP6",
	0x96: "SWAP7",
	0x97: "SWAP8",
	0x98: "SWAP9",
	0x99: "SWAP10",
	0x9a: "SWAP11",
	0x9b: "SWAP12",
	0x9c: "SWAP13",
	0x9d: "SWAP14",
	0x9e: "SWAP15",
	0x9f: "SWAP16",

	0xa0: "LOG0",
	0xa1: "LOG1",
	0xa2: "LOG2",
	0xa3: "LOG3",
	0xa4: "LOG4",

	0xf0: "CREATE",
	0xf1: "CALL",
	0xf2: "CALLCODE",
	0xf3: "RETURN",
	0xf4: "DELEGATECALL",
	0xfd: "REVERT",
	0xfe: "INVALID",
	0xff: "SUICIDE"
}

actions = {
	# opcode : (delta, alpha),
	"INTRET": (0, 0),  # this is fake
	"ASSERT": (1, 0),  # this is fake
	# multiple INTCALL will be added, all fake

	"STOP": (0, 0),
	"ADD": (2, 1),
	"MUL": (2, 1),
	"SUB": (2, 1),
	"DIV": (2, 1),
	"SDIV": (2, 1),
	"MOD": (2, 1),
	"SMOD": (2, 1),
	"ADDMOD": (3, 1),
	"MULMOD": (3, 1),
	"EXP": (2, 1),
	"SIGNEXTEND": (2, 1),
	"LT": (2, 1),
	"GT": (2, 1),
	"SLT": (2, 1),
	"SGT": (2, 1),
	"EQ": (2, 1),
	"ISZERO": (1, 1),
	"AND": (2, 1),
	"OR": (2, 1),
	"XOR": (2, 1),
	"NOT": (1, 1),
	"BYTE": (2, 1),
	"SHA3": (2, 1),
	"ADDRESS": (0, 1),
	"BALANCE": (1, 1),
	"ORIGIN": (0, 1),
	"CALLER": (0, 1),
	"CALLVALUE": (0, 1),
	"CALLDATALOAD": (1, 1),
	"CALLDATASIZE": (0, 1),
	"CALLDATACOPY": (3, 0),
	"CODESIZE": (0, 1),
	"CODECOPY": (3, 0),
	"GASPRICE": (0, 1),
	"EXTCODESIZE": (1, 1),
	"EXTCODECOPY": (4, 0),
	"BLOCKHASH": (1, 1),
	"COINBASE": (0, 1),
	"TIMESTAMP": (0, 1),
	"NUMBER": (0, 1),
	"DIFFICULTY": (0, 1),
	"GASLIMIT": (0, 1),
	"POP": (1, 0),
	"MLOAD": (1, 1),
	"MSTORE": (2, 0),
	"MSTORE8": (2, 0),
	"SLOAD": (1, 1),
	"SSTORE": (2, 0),
	"JUMP": (1, 0),
	"JUMPI": (2, 0),
	"PC": (0, 1),
	"MSIZE": (0, 1),
	"GAS": (0, 1),
	"JUMPDEST": (0, 0),

	"PUSH1": (0, 1, 1),
	"PUSH2": (0, 1, 2),
	"PUSH3": (0, 1, 3),
	"PUSH4": (0, 1, 4),
	"PUSH5": (0, 1, 5),
	"PUSH6": (0, 1, 6),
	"PUSH7": (0, 1, 7),
	"PUSH8": (0, 1, 8),
	"PUSH9": (0, 1, 9),
	"PUSH10": (0, 1, 10),
	"PUSH11": (0, 1, 11),
	"PUSH12": (0, 1, 12),
	"PUSH13": (0, 1, 13),
	"PUSH14": (0, 1, 14),
	"PUSH15": (0, 1, 15),
	"PUSH16": (0, 1, 16),
	"PUSH17": (0, 1, 17),
	"PUSH18": (0, 1, 18),
	"PUSH19": (0, 1, 19),
	"PUSH20": (0, 1, 20),
	"PUSH21": (0, 1, 21),
	"PUSH22": (0, 1, 22),
	"PUSH23": (0, 1, 23),
	"PUSH24": (0, 1, 24),
	"PUSH25": (0, 1, 25),
	"PUSH26": (0, 1, 26),
	"PUSH27": (0, 1, 27),
	"PUSH28": (0, 1, 28),
	"PUSH29": (0, 1, 29),
	"PUSH30": (0, 1, 30),
	"PUSH31": (0, 1, 31),
	"PUSH32": (0, 1, 32),

	"DUP1": (1, 2),
	"DUP2": (2, 3),
	"DUP3": (3, 4),
	"DUP4": (4, 5),
	"DUP5": (5, 6),
	"DUP6": (6, 7),
	"DUP7": (7, 8),
	"DUP8": (8, 9),
	"DUP9": (9, 10),
	"DUP10": (10, 11),
	"DUP11": (11, 12),
	"DUP12": (12, 13),
	"DUP13": (13, 14),
	"DUP14": (14, 15),
	"DUP15": (15, 16),
	"DUP16": (16, 17),

	"SWAP1": (2, 2),
	"SWAP2": (3, 3),
	"SWAP3": (4, 4),
	"SWAP4": (5, 5),
	"SWAP5": (6, 6),
	"SWAP6": (7, 7),
	"SWAP7": (8, 8),
	"SWAP8": (9, 9),
	"SWAP9": (10, 10),
	"SWAP10": (11, 11),
	"SWAP11": (12, 12),
	"SWAP12": (13, 13),
	"SWAP13": (14, 14),
	"SWAP14": (15, 15),
	"SWAP15": (16, 16),
	"SWAP16": (17, 17),

	"LOG0": (2, 0),
	"LOG1": (3, 0),
	"LOG2": (4, 0),
	"LOG3": (5, 0),
	"LOG4": (6, 0),
	"CREATE": (3, 1),
	"CALL": (7, 1),
	"CALLCODE": (7, 1),
	"RETURN": (2, 0),
	"DELEGATECALL": (6, 1),

	"REVERT": (2, 0),
	"INVALID": (0, 0),
	"SUICIDE": (1, 0)
}

push_ops = {
	"PUSH1",
	"PUSH2",
	"PUSH3",
	"PUSH4",
	"PUSH5",
	"PUSH6",
	"PUSH7",
	"PUSH8",
	"PUSH9",
	"PUSH10",
	"PUSH11",
	"PUSH12",
	"PUSH13",
	"PUSH14",
	"PUSH15",
	"PUSH16",
	"PUSH17",
	"PUSH18",
	"PUSH19",
	"PUSH20",
	"PUSH21",
	"PUSH22",
	"PUSH23",
	"PUSH24",
	"PUSH25",
	"PUSH26",
	"PUSH27",
	"PUSH28",
	"PUSH29",
	"PUSH30",
	"PUSH31",
	"PUSH32"
}

dup_ops = {
	"DUP1",
	"DUP2",
	"DUP3",
	"DUP4",
	"DUP5",
	"DUP6",
	"DUP7",
	"DUP8",
	"DUP9",
	"DUP10",
	"DUP11",
	"DUP12",
	"DUP13",
	"DUP14",
	"DUP15",
	"DUP16"
}

swap_ops = {
	"SWAP1",
	"SWAP2",
	"SWAP3",
	"SWAP4",
	"SWAP5",
	"SWAP6",
	"SWAP7",
	"SWAP8",
	"SWAP9",
	"SWAP10",
	"SWAP11",
	"SWAP12",
	"SWAP13",
	"SWAP14",
	"SWAP15",
	"SWAP16"
}

log_ops = {
	"LOG0",
	"LOG1",
	"LOG2",
	"LOG3",
	"LOG4"
}

exit_ops = {
	"RETURN",
	"INVALID",
	"STOP",
	"SUICIDE",
	"REVERT"
}

jump_ops = {
	"JUMP",
	"JUMPI"
}

bin_ops = {
	"SUB"   : "-",
	"ADD"   : "+",
	"EXP" 	: "**",
	"MUL" 	: "*",
	"SDIV" 	: "/",
	"SMOD" 	: "%",
	"OR" 	: "|",
	"DIV" 	: "/",
	"GT" 	: ">",
	"SGT" 	: ">",
	"SLT" 	: "<",
	"LT" 	: "<",
	"EQ" 	: "==",
	"XOR" 	: "^",
	"AND" 	: "&",
	"MOD" 	: "%",
	"BYTE"	: "BYTE",
	"SIGNEXTEND" : "EXT",
}

mono_ops = {
	"NOT"   : "!",
	"ISZERO": "0 ==",		# ???
}

special_ops = {
	"CALLDATASIZE": "calldatasize",
	"CALLER": "msg.sender",
	"TIMESTAMP": "block.timestamp",
	"CALLVALUE": "msg.value",
	"ADDRESS": "self",
	"ORIGIN": "tx.origin",
	"GAS": "msg.gas",
	"NUMBER": "block.number",
	"NOP": "pass"
}

call_ops = {
	"CALL",
	"CALLCODE",
	"DELEGATECALL"
}

mem_write_ops = {
	"CALLDATACOPY",
	"CODECOPY",
	"EXTCODECOPY",
	"MSTORE",
	"MSTORE8",
} | call_ops

mem_read_ops = {
	"MLOAD",
	"SHA3",
	"CREATE",
	"RETURN"
} | log_ops | call_ops

order_ops = {
	"GAS",
	"BALANCE",
	"MSIZE"
}

negate_ops = {
	"GT" : "LEQ",
	"LT" : "GEQ",
	"EQ" : "NEQ"
}

fake_ops = {
	"LEQ"   : "<=",      # fake
	"GEQ"   : ">=",      # fake
	"NEQ"   : "!=",      # fake

	"SL"    : "<<",      # fake
	"SR"    : ">>",      # fake
}

free_ops = set(opcodes.values()) \
   - push_ops \
   - mem_read_ops \
   - mem_write_ops \
   - {"SSTORE", "SLOAD"} \
   - dup_ops \
   - swap_ops \
   - exit_ops \
   - jump_ops


# these operations capture the result of an execution
# SSTORE is handled elsewhere
# effect_ops happens to be a subset of
effect_ops = call_ops | log_ops | {"CREATE", "RETURN"}

# if there is no more access its
throw_away_ops = set(bin_ops.keys()
    + mono_ops.keys()
	+ ["MOVE", "NOP", "PASS"]
	+ special_ops.keys())


INTERNAL_RETURN_OPCODE = "INTRET"

INTERNAL_CALL_OPCODE = "INTCALL"

ADDRESS_MASK = 0xffffffffffffffffffffffffffffffffffffffff
WORD_MASK = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
