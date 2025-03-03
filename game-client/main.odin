package main

import "core:fmt"
import enet "vendor:ENet"

main :: proc() {
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
		fmt.println("It works!")
		data := []u32 {1, 2, 3}
		fmt.println(data)
		packet := enet.packet_create(&data[0], size_of(u32)*3, {.RELIABLE})
		enet.peer_send(peer, 0, packet)
		enet.host_flush(client)
	} else {
		fmt.println("Nay!")
	}
}