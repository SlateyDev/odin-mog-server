package main

import "core:fmt"
import en "vendor:ENet"

main :: proc() {
    en.initialize()
    defer en.deinitialize()

    address: en.Address
    event: en.Event
	peer: ^en.Peer

    client := en.host_create(nil, 1, 2, 0, 0)
    if client == nil {
        fmt.println("Couldn't create socket!")
    }
	defer en.host_destroy(client)

    en.address_set_host_ip(&address, "127.0.0.1\x00")
    address.port = 21070

    fmt.println("Host IP set!")

	peer = en.host_connect(client, &address, 0, 0)
	defer en.peer_reset(peer)

	if peer == nil {
		fmt.println("Yuk!")
	}

	fmt.println("Establishing connection!")

	if en.host_service(client, &event, 1000) > 0 && event.type == .CONNECT {
		fmt.println("It works!")
		data := []u32 {1, 2, 3}
		fmt.println(data)
		packet := en.packet_create(&data[0], size_of(u32)*3, {.RELIABLE})
		en.peer_send(peer, 0, packet)
		en.host_flush(client)
	} else {
		fmt.println("Nay!")
	}
}