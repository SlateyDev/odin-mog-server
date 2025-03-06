package common

import "core:fmt"

MSG_OPCODE :: enum u16 {
	CMSG_LOGIN_CHALLENGE = 16,
	SMSG_LOGIN_CHALLENGE_OK,
	SMSG_LOGIN_CHALLENGE_FAIL,
	CMSG_LOGIN_PROOF,
	SMSG_LOGIN_PROOF_OK,
	SMSG_LOGIN_PROOF_FAIL,
	CMSG_REALMLIST,
	SMSG_REALMLIST_RESPONSE,
}

FAILURE_REASON :: enum u8 {
	BANNED = 3,
	UNKNOWN_ACCOUNT,
	ALREADY_ONLINE,
	NO_TIME,
	BUSY,
	BAD_VERSION,
	SUSPENDED,
}

MessageHeader :: struct {
	opcode: MSG_OPCODE,
	length: u16,
}

FailureMessageHeader :: struct {
	using header: MessageHeader,
	failure: FAILURE_REASON,
}

LoginChallengeHeader :: struct {
	using header: MessageHeader,
	major:        u8,
	minor:        u8,
	build:        u16,
	username_len: u16,
	publicA_len:  u16,
}

LoginChallengeResponseHeader :: struct {
	using header: MessageHeader,
	publicB_len:  u16,
	salt_len:     u16,
}

LoginProofHeader :: struct {
	using header: MessageHeader,
	hash_len:     u16,
}


PrintHexBytesLine :: proc(bytes: ^[]u8) {
	for &i in bytes {
		fmt.printf("%2X", i)
	}
	fmt.println()
}
