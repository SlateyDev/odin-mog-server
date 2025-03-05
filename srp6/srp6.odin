package srp6

import "core:crypto/hash"
import "core:math/big"

SALT_LENGTH_BYTES :: 32
SALT_LENGTH_BITS :: SALT_LENGTH_BYTES * 8

grunt_SRP6_N :: "B79B3E2A87823CAB8F5EBFBF8EB10108535006298B5BADBD5B53E1895E644B89"
grunt_SRP6_g :: 7

//TODO: This need reversing
// bnet_SRP6v1Base_N :: "86A7F6DEEB306CE519770FE37D556F29944132554DED0BD68205E27F3231FEF5A10108238A3150C59CAF7B0B6478691C13A6ACF5E1B5ADAFD4A943D4A21A142B800E8A55F8BFBAC700EB77A7235EE5A609E350EA9FC19F10D921C2FA832E4461B7125D38D254A0BE873DFC27858ACB3F8B9F258461E4373BC3A6C2A9634324AB"
// bnet_SRP6v1Base_g :: 2

//TODO: This need reversing
// bnet_SRP6v2Base_N :: "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
// bnet_SRP6v2Base_g :: 2

srp6_context :: struct {
	g:          ^big.Int,
	N:          ^big.Int,
	k:          ^big.Int,
	PrivateA:   ^big.Int,
	PrivateB:   ^big.Int,
	PublicA:    ^big.Int,
	PublicB:    ^big.Int,
	Salt:       ^big.Int,
	Verifier:   ^big.Int,
	SessionKey: []byte,
}

InitContext :: proc(ctx: ^srp6_context, N: string, g: int) -> (err: big.Error) {
	ctx.g = new(big.Int)
	ctx.N = new(big.Int)
	ctx.k = new(big.Int)
	ctx.PrivateA = new(big.Int)
	ctx.PrivateB = new(big.Int)
	ctx.PublicA = new(big.Int)
	ctx.PublicB = new(big.Int)
	ctx.Salt = new(big.Int)
	ctx.Verifier = new(big.Int)

	big.string_to_int(ctx.N, grunt_SRP6_N, 16) or_return
	big.int_set_from_integer(ctx.g, grunt_SRP6_g) or_return

	return
}

DestroyContext :: proc(ctx: ^srp6_context) {
	big.destroy(ctx.g)
	big.destroy(ctx.N)
	big.destroy(ctx.k)
	big.destroy(ctx.PrivateA)
	big.destroy(ctx.PrivateB)
	big.destroy(ctx.PublicA)
	big.destroy(ctx.PublicB)
	big.destroy(ctx.Salt)
	big.destroy(ctx.Verifier)

	free(ctx.g)
	free(ctx.N)
	free(ctx.k)
	free(ctx.PrivateA)
	free(ctx.PrivateB)
	free(ctx.PublicA)
	free(ctx.PublicB)
	free(ctx.Salt)
	free(ctx.Verifier)

	delete(ctx.SessionKey)
}

CreateRegistration :: proc(
	ctx: ^srp6_context,
	username: string,
	password: string,
) -> (
	err: big.Error,
) {
	big.int_random(ctx.Salt, SALT_LENGTH_BITS) or_return
	// We can set Salt to a specific value for testing
	// big.string_to_int(ctx.Salt, "366349849953456834245893126396224998254948340481") or_return

	un := transmute([]byte)username
	pw := transmute([]byte)password
	salt_bytes_size := big.int_to_bytes_size(ctx.Salt) or_return
	salt_bytes := make([]byte, salt_bytes_size)
	defer delete(salt_bytes)
	big.int_to_bytes_little(ctx.Salt, salt_bytes) or_return

	data := make([]byte, len(un) + len(pw) + 1)
	defer delete(data)
	copy_slice(data[0:], un)
	copy_slice(data[len(un):], transmute([]byte)(string(":")))
	copy_slice(data[len(un) + 1:], pw)
	password_hash := hash.hash(.SHA256, data)
	defer delete(password_hash)

	data2 := make([]byte, len(password_hash) + salt_bytes_size)
	defer delete(data2)
	copy_slice(data2[0:], password_hash)
	copy_slice(data2[len(password_hash):], salt_bytes)

	combined_hash := hash.hash(.SHA256, data2)
	defer delete(combined_hash)

	x := &big.Int{}
	defer big.destroy(x)
	big.int_from_bytes_little(x, combined_hash) or_return

	big.internal_int_powmod(ctx.Verifier, ctx.g, x, ctx.N) or_return

	return
}

ClientLoginChallenge :: proc(ctx: ^srp6_context) -> (err: big.Error) {
	big.int_random(ctx.PrivateA, SALT_LENGTH_BITS) or_return
	big.internal_powmod(ctx.PublicA, ctx.g, ctx.PrivateA, ctx.N) or_return
	return
}

ServerLoginChallenge :: proc(
	ctx: ^srp6_context,
	PublicA: ^big.Int,
	Verifier: ^big.Int,
) -> (
	err: big.Error,
) {
	big.copy(ctx.PublicA, PublicA) or_return

	big.int_random(ctx.PrivateB, SALT_LENGTH_BITS) or_return

	// PublicB = ((k * Verifier) + ModPow(g, b, N)) % N
	temp := &big.Int{}
	defer big.destroy(temp)
	big.mul(temp, ctx.k, Verifier) or_return
	big.internal_powmod(ctx.PublicB, ctx.g, ctx.PrivateB, ctx.N) or_return
	big.add(ctx.PublicB, temp, ctx.PublicB) or_return
	big.mod(ctx.PublicB, ctx.PublicB, ctx.N) or_return

	// u = BigInteger(sha256(concat(PublicA, PublicB)))
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
	u_hash := hash.hash(.SHA256, u_bytes)
	defer delete(u_hash)

	temp_u := &big.Int{}
	defer big.destroy(temp_u)
	big.int_from_bytes_little(temp_u, u_hash) or_return

	// S = ModPow((PublicA * ModPow(Verifier, u, N)), b, N)
	tempS := &big.Int{}
	defer big.destroy(tempS)
	big.internal_powmod(tempS, Verifier, temp_u, ctx.N) or_return
	big.mul(tempS, tempS, ctx.PublicA) or_return
	big.internal_powmod(tempS, tempS, ctx.PrivateB, ctx.N) or_return

	// SessionKey = sha256(S);
	tempS_bytes_size := big.int_to_bytes_size(tempS) or_return
	tempS_bytes := make([]byte, tempS_bytes_size)
	defer delete(tempS_bytes)
	big.int_to_bytes_little(tempS, tempS_bytes) or_return

	ctx.SessionKey = hash.hash(.SHA256, tempS_bytes)

	return
}

ClientLoginProof :: proc(
	ctx: ^srp6_context,
	PublicB: ^big.Int,
	Salt: ^big.Int,
	Username: string,
	Password: string,
) -> (
	err: big.Error,
) {
	big.copy(ctx.PublicB, PublicB) or_return
	big.copy(ctx.Salt, Salt) or_return

	// u = BigInteger(sha256(concat(PublicA, PublicB)))
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
	u_hash := hash.hash(.SHA256, u_bytes)
	defer delete(u_hash)

	temp_u := &big.Int{}
	defer big.destroy(temp_u)
	big.int_from_bytes_little(temp_u, u_hash) or_return

	// passwordHash = sha256(Username + ":" + Password);
	user_pass_bytes := make([]byte, len(Username) + len(Password) + 1)
	defer delete(user_pass_bytes)
	copy_slice(user_pass_bytes[0:], transmute([]byte)(Username))
	copy_slice(user_pass_bytes[len(Username):], transmute([]byte)(string(":")))
	copy_slice(user_pass_bytes[len(Username) + 1:], transmute([]byte)(Password))
	passwordHash := hash.hash(.SHA256, user_pass_bytes)
	defer delete(passwordHash)

	// x = BigInteger(sha256(concat(passwordHash,Salt)))
	salt_bytes_size := big.int_to_bytes_size(ctx.Salt) or_return
	salt_bytes := make([]byte, salt_bytes_size)
	defer delete(salt_bytes)
	big.int_to_bytes_little(ctx.Salt, salt_bytes) or_return

	temp_x := &big.Int{}
	defer big.destroy(temp_x)
	passhash_salt_bytes := make([]byte, len(passwordHash) + salt_bytes_size)
	defer delete(passhash_salt_bytes)
	copy_slice(passhash_salt_bytes[0:], passwordHash)
	copy_slice(passhash_salt_bytes[len(passwordHash):], salt_bytes)
	x_hash := hash.hash(.SHA256, passhash_salt_bytes)
	defer delete(x_hash)
	big.int_from_bytes_little(temp_x, x_hash) or_return

	// S = ModPow(PublicB - k * ModPow(g, x, N), (a + u * x), N)
	tempBase := &big.Int{}
	defer big.destroy(tempBase)
	big.internal_powmod(tempBase, ctx.g, temp_x, ctx.N) or_return
	big.mul(tempBase, tempBase, ctx.k) or_return
	big.sub(tempBase, ctx.PublicB, tempBase) or_return

	tempPow := &big.Int{}
	defer big.destroy(tempPow)
	big.mul(tempPow, temp_u, temp_x) or_return
	big.add(tempPow, ctx.PrivateA, tempPow) or_return

	tempS := &big.Int{}
	defer big.destroy(tempS)
	big.internal_powmod(tempS, tempBase, tempPow, ctx.N) or_return

	// sessionkey = sha256(S)
	tempS_bytes_size := big.int_to_bytes_size(tempS) or_return
	tempS_bytes := make([]byte, tempS_bytes_size)
	defer delete(tempS_bytes)
	big.int_to_bytes_little(tempS, tempS_bytes) or_return

	ctx.SessionKey = hash.hash(.SHA256, tempS_bytes)

	return
}
