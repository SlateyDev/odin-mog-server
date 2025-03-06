package common

import "core:fmt"

MSG :: enum u16 {
	CMSG_LOGIN_CHALLENGE = 16,
	SMSG_LOGIN_CHALLENGE_OK,
	SMSG_LOGIN_CHALLENGE_FAIL,
	CMSG_LOGIN_PROOF,
	SMSG_LOGIN_PROOF_OK,
	SMSG_LOGIN_PROOF_FAIL,
	CMSG_REALMLIST,
	SMSG_REALMLIST_RESPONSE,
}


MessageHeader :: struct {
	opcode: u16,
	length: u16,
}

LoginChallengeHeader :: struct {
	using header: MessageHeader,
	major:        u8,
	minor:        u8,
	revision:     u8,
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
