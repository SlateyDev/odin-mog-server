package main

import "../common"
import "../srp6"
import "core:crypto/hash"
import "core:fmt"
import "core:math/big"
import "core:mem"
import enet "vendor:ENet"

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

	client_srp_context := srp6.srp6_context{}
	srp6.InitContext(&client_srp_context, srp6.grunt_SRP6_N, srp6.grunt_SRP6_g)
	defer srp6.DestroyContext(&client_srp_context)

	if enet.host_service(client, &event, 1000) > 0 && event.type == .CONNECT {
		fmt.println("It works!")

		SendClientLoginChallenge(peer, &client_srp_context, "scott")

		enet.host_flush(client)
	} else {
		fmt.println("Nay!")
	}
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
	public_b: ^big.Int,
	salt: ^big.Int,
	username: string,
	password: string,
) -> (
	err: big.Error,
) {
	srp6.ClientLoginProof(ctx, public_b, salt, username, password) or_return

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

	data_size := size_of(common.MessageHeader) + len(M1)
	data := make([]u8, data_size)
	defer delete(data)

	message := common.MessageHeader{
		opcode = u16(common.MSG.CMSG_LOGIN_PROOF),
		length = u16(size_of(common.MessageHeader) + len(M1)),
	}

	mem.copy(&data[0], &message, size_of(message))
	mem.copy(&data[size_of(message)], raw_data(M1), len(M1))

	packet := enet.packet_create(&data[0], len(data), {.RELIABLE})
	enet.peer_send(peer, 0, packet)

	return
}
