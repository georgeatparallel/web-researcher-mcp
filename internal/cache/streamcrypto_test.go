package cache

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

const streamTestKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func sealStream(t *testing.T, data, aad []byte) []byte {
	t.Helper()
	gcm, err := NewGCM(streamTestKey)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := NewStreamEncrypter(&out, gcm, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func openStream(t *testing.T, sealed, aad []byte) ([]byte, error) {
	t.Helper()
	gcm, err := NewGCM(streamTestKey)
	if err != nil {
		t.Fatal(err)
	}
	return io.ReadAll(NewStreamDecrypter(bytes.NewReader(sealed), gcm, aad))
}

func TestStreamCryptoRoundTrip(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, streamChunkSize - 1, streamChunkSize, streamChunkSize + 1, 3*streamChunkSize + 17} {
		data := make([]byte, size)
		_, _ = rand.Read(data)
		sealed := sealStream(t, data, []byte("aad"))
		if size > 32 && bytes.Contains(sealed, data[:32]) {
			t.Fatalf("size %d: plaintext visible in sealed stream", size)
		}
		got, err := openStream(t, sealed, []byte("aad"))
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestStreamCryptoTamperTruncation(t *testing.T) {
	t.Parallel()
	data := []byte(strings.Repeat("secret-cookie-value", 20000))
	sealed := sealStream(t, data, []byte("aad"))

	cases := map[string]struct {
		mutate func() []byte
		aad    []byte
	}{
		"truncated at chunk boundary": {func() []byte { return sealed[:len(sealed)-(4+len(data)%streamChunkSize+16)] }, []byte("aad")},
		"truncated mid chunk":         {func() []byte { return sealed[:len(sealed)-5] }, []byte("aad")},
		"empty":                       {func() []byte { return nil }, []byte("aad")},
		"flipped byte": {func() []byte {
			c := append([]byte(nil), sealed...)
			c[len(c)/2] ^= 0x01
			return c
		}, []byte("aad")},
		"bad magic": {func() []byte {
			c := append([]byte(nil), sealed...)
			c[0] = 'X'
			return c
		}, []byte("aad")},
		"wrong aad": {func() []byte { return sealed }, []byte("other")},
	}
	for name, tc := range cases {
		if _, err := openStream(t, tc.mutate(), tc.aad); !errors.Is(err, ErrStreamCorrupt) {
			t.Errorf("%s: got %v, want ErrStreamCorrupt", name, err)
		}
	}
}

func TestStreamEncrypterRejectsBadAEAD(t *testing.T) {
	t.Parallel()
	if _, err := NewStreamEncrypter(io.Discard, nil, nil); err == nil {
		t.Fatal("nil AEAD accepted")
	}
}
