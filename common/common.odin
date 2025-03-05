package common

MSG :: enum u16 {
    CMSG_LOGIN_CHALLENGE = 16,
    SMSG_LOGIN_CHALLENGE_OK,
    SMSG_LOGIN_CHALLENGE_FAIL,
    CMSG_LOGIN_PROOF,
    SMSG_LOGIN_PROOF_OK,
    SMSG_LOGIN_PROOF_FAIL,
}


MessageHeader :: struct {
	opcode: u16,
	length: u16,
}

LoginChallengeHeader :: struct {
	using header: MessageHeader,
	major: u8,
	minor: u8,
	revision: u8,
	build: u16,
	username_len: u16,
	publicA_len: u16,
}
