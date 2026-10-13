package cache

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	streamMagic     = "WRS1"
	streamChunkSize = 64 << 10
	streamPrefixLen = 8
	streamFinalBit  = uint32(1) << 31
)

// ErrStreamCorrupt is returned by the stream decrypter when the data is
// truncated, reordered, tampered with, or was sealed with different AAD or key.
var ErrStreamCorrupt = errors.New("encrypted stream is corrupt or truncated")

// streamNonce builds the per-chunk nonce: random 8-byte prefix + chunk counter.
func streamNonce(prefix []byte, counter uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[streamPrefixLen:], counter)
	return nonce
}

// streamAAD binds the caller's AAD, the format tag and the final-chunk flag to
// every chunk, so a truncated stream cannot pass as complete.
func streamAAD(aad []byte, final bool) []byte {
	out := make([]byte, 0, len(streamMagic)+len(aad)+1)
	out = append(out, streamMagic...)
	out = append(out, aad...)
	if final {
		return append(out, 1)
	}
	return append(out, 0)
}

type streamWriter struct {
	w       io.Writer
	gcm     cipher.AEAD
	aad     []byte
	prefix  []byte
	buf     []byte
	counter uint32
	closed  bool
}

// NewStreamEncrypter returns a WriteCloser that seals everything written to it
// into w in 64 KiB AES-GCM chunks. The caller must Close it: the final chunk is
// what lets the reader detect truncation. aad is authenticated, not encrypted.
// A failure of the system RNG is returned as an error; nothing is written in
// plaintext. The GCM nonce size must be 12 bytes (standard AES-GCM).
func NewStreamEncrypter(w io.Writer, gcm cipher.AEAD, aad []byte) (io.WriteCloser, error) {
	if gcm == nil || gcm.NonceSize() != 12 {
		return nil, errors.New("stream encryption needs a 12-byte-nonce AEAD")
	}
	prefix := make([]byte, streamPrefixLen)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return nil, fmt.Errorf("generating stream nonce: %w", err)
	}
	if _, err := w.Write(append([]byte(streamMagic), prefix...)); err != nil {
		return nil, err
	}
	return &streamWriter{w: w, gcm: gcm, aad: aad, prefix: prefix, buf: make([]byte, 0, streamChunkSize)}, nil
}

// Write buffers p and emits a non-final chunk each time a full chunk is held
// and more data arrives.
func (s *streamWriter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("write to closed stream encrypter")
	}
	written := 0
	for len(p) > 0 {
		if len(s.buf) == streamChunkSize {
			if err := s.flush(false); err != nil {
				return written, err
			}
		}
		n := min(len(p), streamChunkSize-len(s.buf))
		s.buf = append(s.buf, p[:n]...)
		p = p[n:]
		written += n
	}
	return written, nil
}

// Close writes the final chunk. It does not close the underlying writer.
func (s *streamWriter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.flush(true)
}

func (s *streamWriter) flush(final bool) error {
	if s.counter == ^uint32(0) {
		return errors.New("stream too long")
	}
	ct := s.gcm.Seal(nil, streamNonce(s.prefix, s.counter), s.buf, streamAAD(s.aad, final))
	length := uint32(len(ct)) // #nosec G115 -- bounded by chunk size + tag
	if final {
		length |= streamFinalBit
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], length)
	if _, err := s.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(ct); err != nil {
		return err
	}
	s.counter++
	s.buf = s.buf[:0]
	return nil
}

type streamReader struct {
	r       io.Reader
	gcm     cipher.AEAD
	aad     []byte
	prefix  []byte
	started bool
	counter uint32
	pending []byte
	done    bool
	err     error
}

// NewStreamDecrypter returns a Reader that opens a stream written by
// NewStreamEncrypter. It returns ErrStreamCorrupt on tampering, a wrong key or
// AAD, or a stream that ends without its final chunk.
func NewStreamDecrypter(r io.Reader, gcm cipher.AEAD, aad []byte) io.Reader {
	return &streamReader{r: r, gcm: gcm, aad: aad}
}

// Read returns decrypted bytes, opening one chunk at a time.
func (s *streamReader) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if s.done {
			return 0, io.EOF
		}
		s.err = s.next()
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *streamReader) next() error {
	if !s.started {
		head := make([]byte, len(streamMagic)+streamPrefixLen)
		if _, err := io.ReadFull(s.r, head); err != nil || string(head[:len(streamMagic)]) != streamMagic {
			return ErrStreamCorrupt
		}
		s.prefix = head[len(streamMagic):]
		s.started = true
	}
	var hdr [4]byte
	if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
		return ErrStreamCorrupt
	}
	raw := binary.BigEndian.Uint32(hdr[:])
	final := raw&streamFinalBit != 0
	length := int(raw &^ streamFinalBit)
	if length < s.gcm.Overhead() || length > streamChunkSize+s.gcm.Overhead() {
		return ErrStreamCorrupt
	}
	ct := make([]byte, length)
	if _, err := io.ReadFull(s.r, ct); err != nil {
		return ErrStreamCorrupt
	}
	pt, err := s.gcm.Open(nil, streamNonce(s.prefix, s.counter), ct, streamAAD(s.aad, final))
	if err != nil {
		return ErrStreamCorrupt
	}
	s.counter++
	s.pending = pt
	s.done = final
	return nil
}
