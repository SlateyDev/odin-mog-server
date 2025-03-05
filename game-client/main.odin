package main

import "../srp6"
import "core:fmt"
import "core:math/big"
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
		data := []u32{1, 2, 3}
		fmt.println(data)
		packet := enet.packet_create(&data[0], size_of(u32) * 3, {.RELIABLE})
		enet.peer_send(peer, 0, packet)
		enet.host_flush(client)
	} else {
		fmt.println("Nay!")
	}
}

//TODO: Move this into a separate library that uses this srp6 to form message, this is the first message sent by the client
SendClientLoginChallenge :: proc(ctx: ^srp6.srp6_context, username: string) -> (err: big.Error) {
	srp6.ClientLoginChallenge(ctx) or_return

	// UDPTransmitter transmitter = UDPTransmitter.CreateObject();
	// transmitter.WriteUint16((UInt16)CMSG_AUTH_LOGON_CHALLENGE);      //opcode
	// transmitter.WriteUint16((UInt16)(9 + USERNAME.Length + PublicABytes.Length));    //packet_length
	// transmitter.WriteUint8(BUILD_MAJOR);
	// transmitter.WriteUint8(BUILD_MINOR);
	// transmitter.WriteUint8(BUILD_REVISION);
	// transmitter.WriteInt16(CLIENT_BUILD);
	// transmitter.WriteUint16((UInt16)USERNAME.Length);
	// transmitter.WriteFixedString(USERNAME);
	// transmitter.WriteUint16((UInt16)PublicABytes.Length);
	// transmitter.WriteFixedBlob(PublicABytes);
	// transmitter.SendTo(loginSocket, loginEndpoint);

	return
}

//TODO: Move this into a separate library that uses this srp6 to form message, this is the first message sent by the client
SendClientLoginProof :: proc(
	ctx: ^srp6.srp6_context,
	public_b: ^big.Int,
	salt: ^big.Int,
	username: string,
	password: string,
) -> (
	err: big.Error,
) {
	srp6.ClientLoginProof(ctx, public_b, salt, username, password) or_return
	// var M1 = sha.ComputeHash(PublicA.ToByteArray().Concat(PublicB.ToByteArray()).Concat(sessionkey).ToArray());

	// using (MemoryStream ms = new MemoryStream()) {
	// 	using(BinaryWriter bw = new BinaryWriter(ms)) {
	// 		bw.Write(M1, 0, M1.Length);
	// 	}

	// 	byte[] messageBody;
	// 	messageBody = ms.ToArray();

	// 	using (MemoryStream ms1 = new MemoryStream()) {
	// 		UDPTransmitter transmitter = UDPTransmitter.CreateObject();
	// 		transmitter.WriteUint16(CMSG_AUTH_LOGON_PROOF);
	// 		transmitter.WriteUint16((UInt16)messageBody.Length);
	// 		transmitter.WriteFixedBlob(messageBody);
	// 		transmitter.SendTo(loginSocket, loginEndpoint);
	// 	}
	// }

	return
}
