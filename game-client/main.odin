package main

import "../common"
import "../srp6"
import "core:crypto/hash"
import "core:fmt"
import "core:math/big"
import "core:mem"
import enet "vendor:ENet"

client_running := true

OpcodeHandler :: struct {
    on_receive: proc(event: ^enet.Event),
}

opcodes: map[u16]OpcodeHandler

test_username := "scott"
test_password := "password"

main :: proc() {
	when ODIN_DEBUG {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		context.allocator = mem.tracking_allocator(&track)

		defer {
			if len(track.allocation_map) > 0 {
				fmt.eprintf("=== %v allocations not freed: ===\n", len(track.allocation_map))
				for _, entry in track.allocation_map {
					fmt.eprintf("- %v bytes @ %v\n", entry.size, entry.location)
				}
			}
			if len(track.bad_free_array) > 0 {
				fmt.eprintf("=== %v incorrect frees: ===\n", len(track.bad_free_array))
				for entry in track.bad_free_array {
					fmt.eprintf("- %p @ %v\n", entry.memory, entry.location)
				}
			}
			mem.tracking_allocator_destroy(&track)
		}
	}

	defer delete(opcodes)
    RegisterOpcodes()

	enet.initialize()
	defer enet.deinitialize()

	address: enet.Address
	event: enet.Event
	peer: ^enet.Peer

	client := enet.host_create(nil, 1, 2, 0, 0)
	if client == nil {
		fmt.println("Couldn't create socket!")
	}
	defer enet.host_destroy(client)

	enet.address_set_host_ip(&address, "127.0.0.1\x00")
	address.port = 21070

	fmt.println("Host IP set!")

	peer = enet.host_connect(client, &address, 0, 0)
	defer enet.peer_reset(peer)

	if peer == nil {
		fmt.println("Yuk!")
	}

	fmt.println("Establishing connection!")

	if enet.host_service(client, &event, 1000) > 0 && event.type == .CONNECT {
		{
			fmt.println("Connected!")
			sessionData := new(ClientSessionData)
			event.peer.data = sessionData
			srp6.InitContext(&sessionData.auth_context, srp6.grunt_SRP6_N, srp6.grunt_SRP6_g)
			SendClientLoginChallenge(peer, &sessionData.auth_context, test_username)
			enet.host_flush(client)
		}

		for client_running {
			for enet.host_service(client, &event, 1000) > 0 {
				#partial switch event.type {
				case .RECEIVE:
					opcode := cast(^u16)event.packet.data

					data := event.packet.data[:event.packet.dataLength]
					fmt.println(event.packet.dataLength, " bytes received")
					common.PrintHexBytesLine(&data)
	
					if opcode^ in opcodes {
						opcodes[opcode^].on_receive(&event)
					}
				case .DISCONNECT:
					fmt.println("Lost Connection!")
					sessionData := cast(^ClientSessionData)event.peer.data
					srp6.DestroyContext(&sessionData.auth_context)
					free(sessionData)
					event.peer.data = nil

					//Here it could look at reconnecting if you want, we are just going to quit though
					client_running = false
				}
			}
		}
	} else {
		fmt.println("Nay!")
	}
}

RegisterOpcodes :: proc() {
    opcodes[u16(common.MSG.SMSG_LOGIN_CHALLENGE_OK)] = OpcodeHandler{on_login_challenge_ok}
    opcodes[u16(common.MSG.SMSG_LOGIN_CHALLENGE_FAIL)] = OpcodeHandler{on_login_challenge_fail}
    opcodes[u16(common.MSG.SMSG_LOGIN_PROOF_OK)] = OpcodeHandler{on_login_proof_ok}
    opcodes[u16(common.MSG.SMSG_LOGIN_PROOF_FAIL)] = OpcodeHandler{on_login_proof_fail}
}

ClientSessionData :: struct {
	auth_context: srp6.srp6_context,
}

on_login_challenge_ok :: proc(event: ^enet.Event) {
	fmt.println("on_login_challenge_ok")

	data := event.packet.data[:event.packet.dataLength]
    header := cast(^common.LoginChallengeResponseHeader)event.packet.data

	sessionData := cast(^ClientSessionData)event.peer.data

	big.int_from_bytes_little(sessionData.auth_context.PublicB, data[size_of(common.LoginChallengeResponseHeader):size_of(common.LoginChallengeResponseHeader) + header.publicB_len])
	big.int_from_bytes_little(sessionData.auth_context.Salt, data[size_of(common.LoginChallengeResponseHeader) + header.publicB_len:size_of(common.LoginChallengeResponseHeader) + header.publicB_len + header.salt_len])

	SendClientLoginProof(event.peer, &sessionData.auth_context, test_username, test_password)
}

on_login_challenge_fail :: proc(event: ^enet.Event) {
	fmt.println("on_login_challenge_fail")

	enet.peer_disconnect(event.peer, 42)
}

on_login_proof_ok :: proc(event: ^enet.Event) {
	fmt.println("on_login_proof_ok")

	// Request realm list

	enet.peer_disconnect(event.peer, 42)
}

on_login_proof_fail :: proc(event: ^enet.Event) {
	fmt.println("on_login_proof_fail")

	enet.peer_disconnect(event.peer, 42)
}

SendClientLoginChallenge :: proc(peer: ^enet.Peer, ctx: ^srp6.srp6_context, username: string) -> (err: big.Error) {
	srp6.ClientLoginChallenge(ctx) or_return

	publicA_bytes_size := big.int_to_bytes_size(ctx.PublicA) or_return
	publicA_bytes := make([]byte, publicA_bytes_size)
	defer delete(publicA_bytes)
	big.int_to_bytes_little(ctx.PublicA, publicA_bytes) or_return
	
	data_size := size_of(common.LoginChallengeHeader) + len(username) + publicA_bytes_size
	data := make([]u8, data_size)
	defer delete(data)

	message := common.LoginChallengeHeader{
		opcode = u16(common.MSG.CMSG_LOGIN_CHALLENGE),
		length = u16(size_of(common.LoginChallengeHeader) + len(username) + publicA_bytes_size),
		major = 4,
		minor = 5,
		revision = 6,
		build = 7,
		username_len = u16(len(username)),
		publicA_len = u16(publicA_bytes_size),
	}

	mem.copy(&data[0], &message, size_of(message))
	mem.copy(&data[size_of(message)], raw_data(username), len(username))
	mem.copy(&data[size_of(message) + len(username)], raw_data(publicA_bytes), publicA_bytes_size)

	packet := enet.packet_create(&data[0], len(data), {.RELIABLE})
	enet.peer_send(peer, 0, packet)

	return
}

SendClientLoginProof :: proc(
	peer: ^enet.Peer,
	ctx: ^srp6.srp6_context,
	username: string,
	password: string,
) -> (
	err: big.Error,
) {
	srp6.ClientLoginProof(ctx, username, password) or_return

	PublicA_bytes_size := big.int_to_bytes_size(ctx.PublicA) or_return
	PublicB_bytes_size := big.int_to_bytes_size(ctx.PublicB) or_return

	PublicA_bytes := make([]u8, PublicA_bytes_size)
	defer delete(PublicA_bytes)
	big.int_to_bytes_little(ctx.PublicA, PublicA_bytes)

	PublicB_bytes := make([]u8, PublicB_bytes_size)
	defer delete(PublicB_bytes)
	big.int_to_bytes_little(ctx.PublicB, PublicB_bytes)

	hash_data := make([]u8, PublicA_bytes_size + PublicB_bytes_size + len(ctx.SessionKey))
	defer delete(hash_data)
	copy(hash_data[0:], PublicA_bytes)
	copy(hash_data[PublicA_bytes_size:], PublicB_bytes)
	copy(hash_data[PublicA_bytes_size + PublicB_bytes_size:], ctx.SessionKey)

	M1 := hash.hash(.SHA256, hash_data)
	defer delete(M1)

	data_size := size_of(common.LoginProofHeader) + len(M1)
	data := make([]u8, data_size)
	defer delete(data)

	message := common.LoginProofHeader{
		opcode = u16(common.MSG.CMSG_LOGIN_PROOF),
		length = u16(size_of(common.LoginProofHeader) + len(M1)),
		hash_len = u16(len(M1)),
	}

	mem.copy(&data[0], &message, size_of(common.LoginProofHeader))
	mem.copy(&data[size_of(common.LoginProofHeader)], raw_data(M1), len(M1))

	packet := enet.packet_create(&data[0], len(data), {.RELIABLE})
	enet.peer_send(peer, 0, packet)

	return
}
