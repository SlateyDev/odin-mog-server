package main

import "../sqlite"
import "core:fmt"
import "core:math/big"
import "core:os"
import "core:path/filepath"
import "core:strings"
import enet "vendor:ENet"
import "srp6"

main :: proc() {
    sqlite.db_check(sqlite.db_init("test.db"))
    defer sqlite.db_check(sqlite.db_destroy())

    sqlite.db_check(do_migrations())

    i := &big.Int{}
    salt := &srp6.Salt{}
    verifier := srp6.Verifier{5,10}
    N := &big.Int{}
    g := &big.Int{}
    k := &big.Int{}

    defer big.destroy(i, N, g, k)

    big.string_to_int(N, srp6.bnet_SRP6v2Base_N, 16)
    big.int_set_from_integer(g, srp6.bnet_SRP6v2Base_g)
    err := srp6.init(i, salt, verifier, N, g, k)
    // _,_,err := srp6.CreateRegistration("username", "password")
    if err != .Okay {
        fmt.println(err)
    }

    start_server()
}

do_migrations :: proc() -> (err : sqlite.Result_Code) {
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
    db_execute_statements(`
        CREATE TABLE IF NOT EXISTS _migrations (
        name VARCHAR(100) PRIMARY KEY,
        datetime default current_timestamp
    );`) or_return

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

db_execute_statements :: proc(statements : string) -> (err : sqlite.Result_Code) {
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
                data := cast([^]u32)event.packet.data
                // value := cast(u32)data^
                values := raw_data(data[0:2])
                array := []u32 {values[0], values[1], values[2]}
                data_len := event.packet.dataLength

                fmt.println("Data received", array, "of size", data_len)
                enet.peer_disconnect(event.peer, 42)
            }
        }
    }
}