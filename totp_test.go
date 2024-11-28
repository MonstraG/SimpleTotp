package totp

import (
	"fmt"
	"testing"
	"time"
)

// example as defined in https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
func TestTruncateRFC4226Example(t *testing.T) {
	input := []byte{
		0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16,
		0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e,
		0x94, 0x5b, 0x55, 0x5a,
	}

	const want = 872921

	got := truncate(input)
	if got != want {
		t.Errorf("got %d; want %d", got, want)
	}
}

// https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
func TestTotp(t *testing.T) {
	const secret = "12345678901234567890"

	var tests = []struct {
		time int64
		want int
	}{
		{59, 287082},
		{1111111109, 81804},
		{1111111111, 50471},
		{1234567890, 5924},
		{2000000000, 279037},
		{20000000000, 353130},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.time), func(t *testing.T) {
			got := At(secret, tt.time)
			if got != tt.want {
				t.Errorf("got %d; want %d", got, tt.want)
			}
		})
	}
}

// Basically no-op
func TestNow(t *testing.T) {
	const secret = "12345678901234567890"
	now := time.Now().Unix()
	want := At(secret, now)
	got := Now(secret)
	if got != want {
		t.Errorf("got %d; want %d", got, want)
	}
}
