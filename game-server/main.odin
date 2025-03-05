package main

import "../sqlite"
import "../srp6"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:strings"
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

	sqlite.db_check(sqlite.db_init("test.db"))
	defer sqlite.db_check(sqlite.db_destroy())
	defer sqlite.db_cache_destroy()

	sqlite.db_check(do_migrations())

	registration_ctx := srp6.srp6_context{}
	srp6.InitContext(&registration_ctx, srp6.grunt_SRP6_N, srp6.grunt_SRP6_g)
	defer srp6.DestroyContext(&registration_ctx)
	err := srp6.CreateRegistration(&registration_ctx, "scott", "password")
	if err != .Okay {
		fmt.println(err)
	}

	//CLIENT/SERVER Test
	client_ctx := srp6.srp6_context{}
	server_ctx := srp6.srp6_context{}
	srp6.InitContext(&client_ctx, srp6.grunt_SRP6_N, srp6.grunt_SRP6_g)
	defer srp6.DestroyContext(&client_ctx)
	srp6.InitContext(&server_ctx, srp6.grunt_SRP6_N, srp6.grunt_SRP6_g)
	defer srp6.DestroyContext(&server_ctx)

	// 1. Client Generates and Sends to server a Login Challenge. Would need to send the username also so server can look up salt and verifier to provide challenge response
	srp6.ClientLoginChallenge(&client_ctx)
	// 2. Server gets Salt and Verifier from db for user, for this test we use registration_ctx for its Salt and Verifier of the newly created user
	srp6.ServerLoginChallenge(&server_ctx, client_ctx.PublicA, registration_ctx.Verifier)
	// 3. Send Salt and PublicB to Client. Don't need to test this, it is just network traffic
	// 4. Client uses PublicB and Salt to Generate and Send a Login Proof. This will also store a SessionKey in client_ctx
	srp6.ClientLoginProof(
		&client_ctx,
		server_ctx.PublicB,
		registration_ctx.Salt,
		"scott",
		"password",
	)
	// 5. At this point client and server both have a session key which should match, if they do, authentication was successful
	fmt.print("Client SessionKey: ")
	PrintHexBytesLine(&client_ctx.SessionKey)
	fmt.print("Server SessionKey: ")
	PrintHexBytesLine(&server_ctx.SessionKey)

	start_server()
}

PrintHexBytesLine :: proc(bytes: ^[]u8) {
	for &i in bytes {
		fmt.printf("%2X", i)
	}
	fmt.println()
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

start_server :: proc() {
	enet.initialize()
	defer enet.deinitialize()

	event: enet.Event

	server := enet.host_create(&{enet.HOST_ANY, 21070}, 4, 4, 0, 0)
	if server == nil {
		fmt.println("Couldn't create socket!")
	}
	defer enet.host_destroy(server)

	for true {
		for enet.host_service(server, &event, 1000) > 0 {
			#partial switch event.type {
			case .CONNECT:
				fmt.println("Incomming connection!")
			case .RECEIVE:
				data := event.packet.data[:event.packet.dataLength]
				// value := cast(u32)data^
				// values := raw_data(data[0:event.packet.dataLength - 1])
				fmt.println(event.packet.dataLength, " bytes received")
                PrintHexBytesLine(&data)
				// array := []u8{data[0], data[1], data[2]}
				// data_len := event.packet.dataLength

				// fmt.println("Data received", array, "of size", data_len)
				enet.peer_disconnect(event.peer, 42)
			}
		}
	}
}
