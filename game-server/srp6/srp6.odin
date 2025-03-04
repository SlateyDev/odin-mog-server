package srp6

import "core:crypto/hash"
import "core:fmt"
import "core:math/big"

SALT_LENGTH_BYTES :: 32
SALT_LENGTH_BITS :: SALT_LENGTH_BYTES * 8
Salt :: [SALT_LENGTH_BYTES]u8
Verifier :: []u8

grunt_SRP6_N :: "B79B3E2A87823CAB8F5EBFBF8EB10108535006298B5BADBD5B53E1895E644B89"
grunt_SRP6_g :: 7

//TODO: This need reversing
bnet_SRP6v1Base_N :: "86A7F6DEEB306CE519770FE37D556F29944132554DED0BD68205E27F3231FEF5A10108238A3150C59CAF7B0B6478691C13A6ACF5E1B5ADAFD4A943D4A21A142B800E8A55F8BFBAC700EB77A7235EE5A609E350EA9FC19F10D921C2FA832E4461B7125D38D254A0BE873DFC27858ACB3F8B9F258461E4373BC3A6C2A9634324AB"
bnet_SRP6v1Base_g :: 2

//TODO: This need reversing
bnet_SRP6v2Base_N :: "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
bnet_SRP6v2Base_g :: 2

s: ^Salt
I: ^big.Int
b: ^big.Int
B: ^big.Int
v: ^big.Int

init :: proc(
	i: ^big.Int,
	salt: ^Salt,
	verifier: Verifier,
	N: ^big.Int,
	g: ^big.Int,
	k: ^big.Int,
) -> (
	err: big.Error,
) {
	b = new(big.Int)
	B = new(big.Int)
	v = new(big.Int)

	s = salt
	I = i
	CalculatePrivateB(N) or_return
	big.int_from_bytes_little(v, verifier) or_return
	CalculatePublicB(N, g, k) or_return

    string_I := big.int_itoa_string(I, 16) or_return
    defer delete(string_I)
    string_b := big.int_itoa_string(b, 16) or_return
    defer delete(string_b)
    string_v := big.int_itoa_string(v, 16) or_return
    defer delete(string_v)
    string_B := big.int_itoa_string(B, 16) or_return
    defer delete(string_B)
	fmt.println("I: ", string_I)
	fmt.println("b: ", string_b)
	fmt.println("v: ", string_v)
	fmt.println("B: ", string_B)
	return
}

deinit :: proc() {
	big.destroy(b, B, v)
	free(b)
	free(B)
	free(v)
}

CalculatePrivateB :: proc(N: ^big.Int) -> (err: big.Error) {
	bits := big.count_bits(N) or_return
	big.int_random(b, bits) or_return
	temp := &big.Int{}
	defer big.destroy(temp)
	big.sub(temp, N, 1) or_return
	big.int_mod(b, b, temp) or_return

    string_b := big.int_itoa_string(b) or_return
    defer delete(string_b)

	fmt.println(string_b)
	return
}

CalculatePublicB :: proc(N: ^big.Int, g: ^big.Int, k: ^big.Int) -> (err: big.Error) {
	temp := &big.Int{}
	defer big.destroy(temp)
	big.internal_powmod(temp, g, b, N) or_return
	temp2 := &big.Int{}
	defer big.destroy(temp2)
	big.mul(temp2, v, k) or_return
	big.add(temp, temp, temp2) or_return
	big.mod(B, temp, N) or_return
	//     return (g.ModExp(b, N) + (v * k)) % N;
	return
}


CreateRegistration :: proc(
	username: string,
	password: string,
) -> (
	salt: Salt,
	verifier: Verifier,
	err: big.Error,
) {
	temp_salt := &big.Int{}
	temp_verifier := &big.Int{}
	temp_N := &big.Int{}
	temp_g := &big.Int{}
	defer big.destroy(temp_salt, temp_verifier, temp_N, temp_g)

    // TODO: Change this back to use a random int once testing is completed
    big.int_random(temp_salt, SALT_LENGTH_BITS) or_return
    // big.string_to_int(temp_salt, "366349849953456834245893126396224998254948340481") or_return

	big.string_to_int(temp_N, grunt_SRP6_N, 16) or_return
	big.int_set_from_integer(temp_g, grunt_SRP6_g) or_return

	un := transmute([]byte)username
	pw := transmute([]byte)password
	salt_bytes_size := big.int_to_bytes_size(temp_salt) or_return
	salt_bytes := make([]byte, salt_bytes_size)
	defer delete(salt_bytes)
	big.int_to_bytes_little(temp_salt, salt_bytes) or_return

	data := make([]byte, len(un) + len(pw) + 1)
	defer delete(data)
	copy_slice(data[0:], un)
	copy_slice(data[len(un):], transmute([]byte)(string(":")))
	copy_slice(data[len(un) + 1:], pw)
	password_hash := hash.hash_bytes(.SHA256, data)
    defer delete(password_hash)

    // fmt.println("passwordSalt: ", big.int_itoa_string(temp_salt, 16))
	// fmt.print("passwordHash: ")
    // PrintHexBytesLine(&password_hash)

    data2 := make([]byte, len(password_hash) + salt_bytes_size)
    defer delete(data2)
    copy_slice(data2[0:], password_hash)
    copy_slice(data2[len(password_hash):], salt_bytes)

    // fmt.print("passwordHash + salt: ")
    // PrintHexBytesLine(&data2)
    combined_hash := hash.hash_bytes(.SHA256, data2)
    defer delete(combined_hash)

    // fmt.print("hash: ")
    // PrintHexBytesLine(&combined_hash)

    x := &big.Int{}
    defer big.destroy(x)
    big.int_from_bytes_little(x, combined_hash) or_return
    // fmt.println("x: ", big.int_itoa_string(x, 16))

    big.internal_int_powmod(temp_verifier, temp_g, x, temp_N) or_return

    salt_string := big.int_itoa_string(temp_salt) or_return
    defer delete(salt_string)
    verifier_string := big.int_itoa_string(temp_verifier) or_return
    defer delete(verifier_string)

    fmt.println("salt: ", salt_string)
    fmt.println("verifier: ", verifier_string)

    // fmt.println("(", big.int_itoa_string(temp_g, 16), "^", big.int_itoa_string(x, 16) ,") % ", big.int_itoa_string(temp_N, 16), "= ", big.int_itoa_string(temp_verifier, 16))

	return
}

PrintHexBytesLine :: proc(bytes: ^[]u8) {
    for &i in bytes {
        fmt.printf("%2X", i)
    }
    fmt.println()
}

srp6_context :: struct {
	g: ^big.Int,
	N: ^big.Int,
	k: ^big.Int,
	PublicA: ^big.Int,
	PublicB: ^big.Int,
	Salt: ^big.Int,
	a: ^big.Int,
}

InitContext :: proc(ctx: ^srp6_context) -> (err: big.Error) {
	ctx.g = new(big.Int)
	ctx.N = new(big.Int)
	ctx.k = new(big.Int)
	ctx.PublicA = new(big.Int)
	ctx.PublicB = new(big.Int)
	ctx.Salt = new(big.Int)
	ctx.a = new(big.Int)
	return
}

DestroyContext :: proc(ctx: ^srp6_context) {
	big.destroy(ctx.g)
	big.destroy(ctx.N)
	big.destroy(ctx.k)
	big.destroy(ctx.PublicA)
	big.destroy(ctx.PublicB)
	big.destroy(ctx.Salt)
	big.destroy(ctx.a)

	free(ctx.g)
	free(ctx.N)
	free(ctx.k)
	free(ctx.PublicA)
	free(ctx.PublicB)
	free(ctx.Salt)
	free(ctx.a)
}

AuthLoginChallenge :: proc(ctx: ^srp6_context) -> (err: big.Error) {
	big.int_random(ctx.a, SALT_LENGTH_BITS) or_return

	big.string_to_int(ctx.N, grunt_SRP6_N, 16) or_return
	big.int_set_from_integer(ctx.g, grunt_SRP6_g) or_return
	big.internal_powmod(ctx.PublicA, ctx.g, ctx.a, ctx.N) or_return

	// a_bytes_size := big.int_to_bytes_size(publicA) or_return
	// a_bytes := make([]byte, a_bytes_size)
	// defer delete(a_bytes)
	// big.int_to_bytes_little(publicA, a_bytes) or_return

// 	UDPTransmitter transmitter = UDPTransmitter.CreateObject();
// 	transmitter.WriteUint16((UInt16)CMSG_AUTH_LOGON_CHALLENGE);      //opcode
// 	transmitter.WriteUint16((UInt16)(9 + USERNAME.Length + PublicABytes.Length));    //packet_length
// 	transmitter.WriteUint8(BUILD_MAJOR);
// 	transmitter.WriteUint8(BUILD_MINOR);
// 	transmitter.WriteUint8(BUILD_REVISION);
// 	transmitter.WriteInt16(CLIENT_BUILD);
// 	transmitter.WriteUint16((UInt16)USERNAME.Length);
// 	transmitter.WriteFixedString(USERNAME);
// 	transmitter.WriteUint16((UInt16)PublicABytes.Length);
// 	transmitter.WriteFixedBlob(PublicABytes);
// 	transmitter.SendTo(loginSocket, loginEndpoint);

	return
}

AuthLoginProof :: proc(
	ctx: ^srp6_context,
	PublicB: ^big.Int,
	Salt: ^big.Int,
	Username: string,
	Password: string,
) -> (err: big.Error) {
	big.copy(ctx.PublicB, PublicB)

	// var u = new BigInteger(sha.ComputeHash(PublicA.ToByteArray().Concat(PublicB.ToByteArray()).ToArray()).Concat(new byte[] { 0 }).ToArray());
	PublicA_byte_count := big.int_to_bytes_size(ctx.PublicA) or_return
	PublicB_byte_count := big.int_to_bytes_size(ctx.PublicB) or_return

	PublicA_bytes := make([]byte, PublicA_byte_count)
	defer delete(PublicA_bytes)
	PublicB_bytes := make([]byte, PublicB_byte_count)
	defer delete(PublicB_bytes)

	big.int_to_bytes_little(ctx.PublicA, PublicA_bytes) or_return
	big.int_to_bytes_little(ctx.PublicB, PublicB_bytes) or_return

	u_bytes := make([]byte, len(PublicA_bytes) + len(PublicB_bytes))
	defer delete(u_bytes)
	copy_slice(u_bytes[0:], PublicA_bytes)
	copy_slice(u_bytes[len(PublicA_bytes):], PublicB_bytes)
	u_hash := hash.hash_bytes(.SHA256, u_bytes)
    defer delete(u_hash)

	temp_u := &big.Int{}
	defer big.destroy(temp_u)
	big.int_from_bytes_little(temp_u, u_hash) or_return

	// byte[] passwordHash = sha.ComputeHash(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", USERNAME, PASSWORD.ToUpper())));
	user_pass_bytes := make([]byte, len(Username) + len(Password) + 1)
	defer delete(user_pass_bytes)
	copy_slice(user_pass_bytes[0:], transmute([]byte)(Username))
	copy_slice(user_pass_bytes[len(Username):], transmute([]byte)(string(":")))
	copy_slice(user_pass_bytes[len(Username) + 1:], transmute([]byte)(Password))
	passwordHash := hash.hash_bytes(.SHA256, user_pass_bytes)
    defer delete(passwordHash)

	// var x = new BigInteger(sha.ComputeHash(passwordHash.Concat(Salt.ToByteArray()).ToArray()).Concat(new byte[] { 0 }).ToArray());
	salt_bytes_size := big.int_to_bytes_size(Salt) or_return
	salt_bytes := make([]byte, salt_bytes_size)
	defer delete(salt_bytes)
	big.int_to_bytes_little(Salt, salt_bytes) or_return

	temp_x := &big.Int{}
	defer big.destroy(temp_x)
    passhash_salt_bytes := make([]byte, len(passwordHash) + salt_bytes_size)
    defer delete(passhash_salt_bytes)
    copy_slice(passhash_salt_bytes[0:], passwordHash)
    copy_slice(passhash_salt_bytes[len(passwordHash):], salt_bytes)
    x_hash := hash.hash_bytes(.SHA256, passhash_salt_bytes)
    defer delete(x_hash)
	big.int_from_bytes_little(temp_x, x_hash) or_return
	
	// var S = BigInteger.ModPow(PublicB - k * BigInteger.ModPow(g, x, N), (a + u * x), N);
	tempBase := &big.Int{}
	defer big.destroy(tempBase)
	big.internal_powmod(tempBase, ctx.g, temp_x, ctx.N) or_return
	big.mul(tempBase, tempBase, ctx.k) or_return
	big.sub(tempBase, ctx.PublicB, tempBase) or_return

	tempPow := &big.Int{}
	defer big.destroy(tempPow)
	big.mul(tempPow, temp_u, temp_x) or_return
	big.add(tempPow, ctx.a, tempPow) or_return

	tempS := &big.Int{}
	defer big.destroy(tempS)
	big.internal_powmod(tempS, tempBase, tempPow, ctx.N) or_return

	tempS_bytes_size := big.int_to_bytes_size(tempS) or_return
	tempS_bytes := make([]byte, tempS_bytes_size)
	defer delete(tempS_bytes)
	big.int_to_bytes_little(tempS, tempS_bytes) or_return

	// var sessionkey = sha.ComputeHash(S.ToByteArray());
	sessionKey := hash.hash(.SHA256, tempS_bytes)
	defer delete(sessionKey)

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