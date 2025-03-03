package srp6

import "core:math/big"

SALT_LENGTH :: 32
Salt :: [SALT_LENGTH]u8
Verifier :: []u8

grunt_SRP6_N :: "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
grunt_SRP6_g :: 7

bnet_SRP6v1Base_N :: "86A7F6DEEB306CE519770FE37D556F29944132554DED0BD68205E27F3231FEF5A10108238A3150C59CAF7B0B6478691C13A6ACF5E1B5ADAFD4A943D4A21A142B800E8A55F8BFBAC700EB77A7235EE5A609E350EA9FC19F10D921C2FA832E4461B7125D38D254A0BE873DFC27858ACB3F8B9F258461E4373BC3A6C2A9634324AB"
bnet_SRP6v1Base_g :: 2

bnet_SRP6v2Base_N :: "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
bnet_SRP6v2Base_g :: 2

s : ^Salt
I : ^big.Int
b : ^big.Int
B : ^big.Int
v : ^Verifier

init :: proc(i : ^big.Int, salt : ^Salt, verifier : ^Verifier, N : ^big.Int, g : ^big.Int, k : ^big.Int) -> (err: big.Error) {
    s = salt
    I = i
    b = CalculatePrivateB(N) or_return
    v = verifier
    B = CalculatePublicB(N, g, k) or_return
    return
}

deinit :: proc() {
    big.destroy(I, b, B)
}

CalculatePrivateB :: proc(N: ^big.Int) -> (val: ^big.Int, err: big.Error) {
    val = &big.Int {}
    bits := big.count_bits(N) or_return
    big.int_random(val, bits) or_return
    temp := &big.Int {}
    defer big.destroy(temp)
    big.sub(temp, N, 1)
    big.int_mod(val, val, temp) or_return
    return
}

CalculatePublicB :: proc(N: ^big.Int, g: ^big.Int, k: ^big.Int) -> (val: ^big.Int, err: big.Error) {
    val = &big.Int {}
//     return (g.ModExp(b, N) + (v * k)) % N;
    return
}