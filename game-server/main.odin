package main

import "../sqlite"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import en "vendor:ENet"

main :: proc() {
    sqlite.db_check(sqlite.db_init("test.db"))
    defer sqlite.db_check(sqlite.db_destroy())

    f, err := os.open("migrations")
    defer os.close(f)

    if err != os.ERROR_NONE {
        fmt.println("Could not open migrations folder for reading", err)
        os.exit(1)
    }

    fis: []os.File_Info
    defer os.file_info_slice_delete(fis)

    fis, err = os.read_dir(f, -1)
    if err != os.ERROR_NONE {
        fmt.println("Could not read migrations folder", err)
        os.exit(2)
    }

    for fi in fis {
		_, name := filepath.split(fi.fullpath)
        if filepath.ext(fi.fullpath) != ".sql" do continue

		if fi.is_dir {
			fmt.printfln("%v (directory)", name)
		} else {
			fmt.printfln("%v (%v bytes)", name, fi.size)

            data, _ := os.read_entire_file(fi.fullpath)
            defer delete(data)
        
            it := string(data)
            for statement in strings.split_by_byte_iterator(&it, ';') {
                fmt.println("[STATEMENT]: ", statement)
                fmt.println()
            //     sqlite.db_check(sqlite.db_execute_simple(statement))
            }
        }
	}

    en.initialize()
    defer en.deinitialize()

    event: en.Event

    server := en.host_create(&{en.HOST_ANY, 21070}, 4, 4, 0, 0)
    if server == nil {
        fmt.println("Couldn't create socket!")
    }
    defer en.host_destroy(server)

    for true {
        for en.host_service(server, &event, 1000) > 0 {
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
                en.peer_disconnect(event.peer, 42)
            }
        }
    }
}