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

	fmt.println("I: ", big.int_itoa_string(I, 16))
	fmt.println("b: ", big.int_itoa_string(b, 16))
	fmt.println("v: ", big.int_itoa_string(v, 16))
	fmt.println("B: ", big.int_itoa_string(B, 16))
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

	fmt.println(big.int_itoa_string(b))
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


CalculateX :: proc(username: string, password: string, salt: Salt) {

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