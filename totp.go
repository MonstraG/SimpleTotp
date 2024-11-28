package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"math"
	"strconv"
	"time"
)

// how long should the TOTP be, equivalent to Digit parameter
// as defined in https://datatracker.ietf.org/doc/html/rfc4226#appendix-E.1
const digitCount = 6

// precomputed value like `1_000_000` to take modulo by in truncate
var digitModulo = (int)(math.Pow10(digitCount))

// t0 parameter as defined in https://datatracker.ietf.org/doc/html/rfc6238#section-4.2
const t0 = 0

// timeStep parameter, equivalent to Time Step X
// as defined in https://datatracker.ietf.org/doc/html/rfc6238#section-4.2
const timeStep = 30

// hmacSha is equivalent to hmac_sha function from reference implementation
// as defined in https://datatracker.ietf.org/doc/html/rfc6238#appendix-A
func hmacSha(input, key []byte) []byte {
	hash := hmac.New(sha1.New, key)
	hash.Write(input)
	return hash.Sum(nil)
}

// dt as defined in https://datatracker.ietf.org/doc/html/rfc4226#section-5.3
func dt(input []byte) int {
	if len(input) != 20 {
		panic("dt input length must be 20, got length " + strconv.Itoa(len(input)))
	}
	var offset = input[19] & 0xf
	return int(input[offset]&0x7f)<<24 | int(input[offset+1]&0xff)<<16 | int(input[offset+2]&0xff)<<8 | int(input[offset+3]&0xff)
}

// truncate as defined in https://datatracker.ietf.org/doc/html/rfc4226#section-5.3
func truncate(input []byte) int {
	number := dt(input)
	return number % digitModulo
}

// hotp as defined in https://datatracker.ietf.org/doc/html/rfc4226
func hotp(counter, secret []byte) int {
	return truncate(hmacSha(counter, secret))
}

// timeToBytes performs first 3 operations from the `for` loop from the main function of reference
// implementation as defined in https://datatracker.ietf.org/doc/html/rfc6238#appendix-A
func timeToBytes(unixTime int64) []byte {
	var t = (unixTime - t0) / timeStep
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(t))
	return buf
}

// At gives TOTP as a number from a given secret at given time
func At(secret string, unixTime int64) int {
	return hotp(timeToBytes(unixTime), []byte(secret))
}

// Now gives TOTP as a number from given secret at current time:
// it just calls At with time.Now
func Now(secret string) int {
	return At(secret, time.Now().Unix())
}
