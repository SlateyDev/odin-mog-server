package main

import "../common"
import "../sqlite"
import "../srp6"
import "core:crypto/hash"
import "core:fmt"
import "core:math/big"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:strings"
import enet "vendor:ENet"

OpcodeHandler :: struct {
	on_receive: proc(event: ^enet.Event),
}

opcodes: map[u16]OpcodeHandler

create_test_user :: false
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

	sqlite.db_check(sqlite.db_init("test.db"))
	defer sqlite.db_check(sqlite.db_destroy())
	defer sqlite.db_cache_destroy()

	sqlite.db_check(do_migrations())

	if create_test_user {
		registration_ctx := srp6.srp6_context{}
		srp6.InitContext(&registration_ctx, srp6.grunt_SRP6_N, srp6.grunt_SRP6_g)
		defer srp6.DestroyContext(&registration_ctx)
		err := srp6.CreateRegistration(&registration_ctx, test_username, test_password)
		if err != .Okay {
			fmt.println(err)
		} else {
			verifier, _ := big.itoa(registration_ctx.Verifier, 16)
			salt, _ := big.itoa(registration_ctx.Salt, 16)
			//Delete the test user if it already exists
			sqlite.db_execute("DELETE FROM account WHERE username = ?1", test_username)
			//Add the test user to the database
			sqlite.db_execute(
				"INSERT INTO account (username, verifier, salt) values (?1, ?2, ?3)",
				test_username,
				verifier,
				salt,
			)
			delete(verifier)
			delete(salt)
		}
	}

	start_server()
}

RegisterOpcodes :: proc() {
	opcodes[u16(common.MSG.CMSG_LOGIN_CHALLENGE)] = OpcodeHandler{on_login_challenge}
	opcodes[u16(common.MSG.CMSG_LOGIN_PROOF)] = OpcodeHandler{on_login_proof}
}

on_login_challenge :: proc(event: ^enet.Event) {
	fmt.println("on_login_challenge")

	data := event.packet.data[:event.packet.dataLength]
	header := cast(^common.LoginChallengeHeader)event.packet.data

	username := string(
		data[size_of(common.LoginChallengeHeader):size_of(common.LoginChallengeHeader) +
		header.username_len],
	)

	sessionData := cast(^sessionData)event.peer.data
	sessionData.username = username
	big.int_from_bytes_little(
		sessionData.auth_context.PublicA,
		data[size_of(common.LoginChallengeHeader) +
		header.username_len:size_of(common.LoginChallengeHeader) +
		header.username_len +
		header.publicA_len],
	)

	AccountInfo :: struct {
		id:       int,
		verifier: string,
		salt:     string,
	}

	account_data := AccountInfo{}

	dberr := sqlite.db_select(
		"FROM account where username = ?1",
		account_data,
		sessionData.username,
	)
	fmt.println(dberr)
	fmt.println(account_data)

	big.string_to_int(sessionData.auth_context.Verifier, account_data.verifier, 16)
	big.string_to_int(sessionData.auth_context.Salt, account_data.salt, 16)

	srp6.ServerLoginChallenge(&sessionData.auth_context)

	publicB_bytes_size, _ := big.int_to_bytes_size(sessionData.auth_context.PublicB)
	publicB_bytes := make([]byte, publicB_bytes_size)
	defer delete(publicB_bytes)
	big.int_to_bytes_little(sessionData.auth_context.PublicB, publicB_bytes)

	salt_bytes_size, _ := big.int_to_bytes_size(sessionData.auth_context.Salt)
	salt_bytes := make([]byte, salt_bytes_size)
	defer delete(salt_bytes)
	big.int_to_bytes_little(sessionData.auth_context.Salt, salt_bytes)

	response_header := common.LoginChallengeResponseHeader {
		opcode      = u16(common.MSG.SMSG_LOGIN_CHALLENGE_OK),
		length      = u16(
			size_of(common.LoginChallengeResponseHeader) + publicB_bytes_size + salt_bytes_size,
		),
		publicB_len = u16(publicB_bytes_size),
		salt_len    = u16(salt_bytes_size),
	}

	response := make([]u8, size_of(response_header) + publicB_bytes_size + salt_bytes_size)
    defer delete(response)
	mem.copy(&response[0], &response_header, size_of(response_header))
	mem.copy(&response[size_of(response_header)], raw_data(publicB_bytes), publicB_bytes_size)
	mem.copy(
		&response[size_of(response_header) + publicB_bytes_size],
		raw_data(salt_bytes),
		salt_bytes_size,
	)

	packet := enet.packet_create(&response[0], len(response), {.RELIABLE})
	enet.peer_send(event.peer, 0, packet)
	enet.host_flush(event.peer.host)
}

on_login_proof :: proc(event: ^enet.Event) {
	fmt.println("on_login_proof")

	sessionData := cast(^sessionData)event.peer.data
	ctx := &sessionData.auth_context

	data := event.packet.data[:event.packet.dataLength]
	header := cast(^common.LoginProofHeader)event.packet.data
	client_hash := data[size_of(common.LoginProofHeader):size_of(common.LoginProofHeader) +
	header.hash_len]

	//Generate our hash
	PublicA_bytes_size, _ := big.int_to_bytes_size(ctx.PublicA)
	PublicB_bytes_size, _ := big.int_to_bytes_size(ctx.PublicB)

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

	server_hash := hash.hash(.SHA256, hash_data)
	defer delete(server_hash)

	//Compare it against the hash the client sent

	// fmt.print("Server Hash: ")
	// common.PrintHexBytesLine(&M1)
	// fmt.print("Client Hash: ")
	// common.PrintHexBytesLine(&client_hash)

	if (mem.compare(server_hash, client_hash) == 0) {
		response := common.MessageHeader {
			opcode = u16(common.MSG.SMSG_LOGIN_PROOF_OK),
			length = size_of(common.MessageHeader),
		}
		packet := enet.packet_create(&response, size_of(common.MessageHeader), {.RELIABLE})
		enet.peer_send(event.peer, 0, packet)
		enet.host_flush(event.peer.host)
	} else {
		//Wrong pass
		response := common.MessageHeader {
			opcode = u16(common.MSG.SMSG_LOGIN_PROOF_FAIL),
			length = size_of(common.MessageHeader),
		}
		packet := enet.packet_create(&response, size_of(common.MessageHeader), {.RELIABLE})
		enet.peer_send(event.peer, 0, packet)
		enet.host_flush(event.peer.host)
		enet.peer_disconnect_later(event.peer, 42)
	}
}

do_migrations :: proc() -> (err: sqlite.Result_Code) {
	f, file_error := os.open("migrations")
	defer os.close(f)

	if file_error != os.ERROR_NONE {
		fmt.println("Could not open migrations folder for reading", err)
		os.exit(1)
	}

	fis: []os.File_Info
	defer os.file_info_slice_delete(fis)

	fis, file_error = os.read_dir(f, -1)
	if file_error != os.ERROR_NONE {
		fmt.println("Could not read migrations folder", err)
		os.exit(2)
	}

	fmt.println("Starting DB Migrations")
	db_execute_statements(
		`
        CREATE TABLE IF NOT EXISTS _migrations (
        name VARCHAR(100) PRIMARY KEY,
        datetime default current_timestamp
    );`,
	) or_return

	for fi in fis {
		_, name := filepath.split(fi.fullpath)
		if filepath.ext(fi.fullpath) != ".sql" do continue

		if fi.is_dir {
			// fmt.printfln("%v (directory)", name)
		} else {
			fmt.printf("%v (%v bytes) - ", name, fi.size)

			stmt := sqlite.db_cache_prepare("SELECT 1 FROM _migrations WHERE name = ?1") or_return
			sqlite.db_bind(stmt, name) or_return
			result := sqlite.step(stmt)
			if result == .DONE {
				data, _ := os.read_entire_file(fi.fullpath)
				defer delete(data)

				db_execute_statements(string(data)) or_return

				sqlite.db_execute("INSERT INTO _migrations (name) VALUES (?1)", name) or_return
				fmt.println("Migrated!")
			} else if result != .ROW {
				fmt.println("ERROR!")
				return result
			} else {
				fmt.println("Exists. Skipping")
			}
		}
	}

	return
}

db_execute_statements :: proc(statements: string) -> (err: sqlite.Result_Code) {
	it := statements
	for statement in strings.split_by_byte_iterator(&it, ';') {
		if len(strings.trim_space(statement)) == 0 do continue
		sqlite.db_execute_simple(statement) or_return
	}
	return
}

sessionData :: struct {
	auth_context: srp6.srp6_context,
	username:     string,
}

server_running := true

start_server :: proc() {
	enet.initialize()
	defer enet.deinitialize()

	event: enet.Event

	server := enet.host_create(&{enet.HOST_ANY, 21070}, 4, 4, 0, 0)
	if server == nil {
		fmt.println("Couldn't create socket!")
	}
	defer enet.host_destroy(server)

	for server_running {
		for enet.host_service(server, &event, 1000) > 0 {
			#partial switch event.type {
			case .CONNECT:
				fmt.println("Incomming connection")
				sessionData := new(sessionData)
				event.peer.data = sessionData
				srp6.InitContext(&sessionData.auth_context, srp6.grunt_SRP6_N, srp6.grunt_SRP6_g)
			case .RECEIVE:
				opcode := cast(^u16)event.packet.data

				data := event.packet.data[:event.packet.dataLength]
				fmt.println(event.packet.dataLength, " bytes received")
				common.PrintHexBytesLine(&data)

				if opcode^ in opcodes {
					opcodes[opcode^].on_receive(&event)
				}
			case .DISCONNECT:
				fmt.println("Disconnection!")
				sessionData := cast(^sessionData)event.peer.data
				srp6.DestroyContext(&sessionData.auth_context)
				free(sessionData)
				event.peer.data = nil
			}
		}
	}
}
