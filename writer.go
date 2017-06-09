package acs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"sync"
)

// A Writer is an io.WriteCloser. Writes to a Writer are encrypted (AES-CBC) and written to w.
type Writer struct {
	closed    bool
	beginning bool
	mu        sync.Mutex
	w         io.Writer
	iv        []byte
	block     cipher.Block
	mode      cipher.BlockMode
	pending   []byte // pending data
}

// NewWriter returns an AES CBC writer.
func NewWriter(w io.Writer, key []byte) (*Writer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, block.BlockSize())
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return &Writer{
		beginning: true,
		w:         w,
		block:     block,
		iv:        iv,
		mode:      cipher.NewCBCEncrypter(block, iv),
	}, err
}

// Write implements io.Writer interface.
func (w *Writer) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		panic("acs: writes on a closed writer")
	}

	if w.beginning {
		_, err = w.w.Write(w.iv)
		if err != nil {
			return
		}
		w.beginning = false
	}

	p = append(w.pending, p...)
	run := (len(p) / w.block.BlockSize()) * w.block.BlockSize()
	w.pending = p[run:]
	if run == 0 {
		// Not enough data to write a complete block
		return
	}

	data := make([]byte, run)
	w.mode.CryptBlocks(data, p[:run])
	_, err = w.w.Write(data)

	n = len(p)

	return
}

// Close implements io.Close interface.
func (w *Writer) Close() (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.pending) > 0 {
		w.pending = PKCS5Padding(w.pending, w.block.BlockSize())
		w.mode.CryptBlocks(w.pending, w.pending)
		_, err = w.w.Write(w.pending)
	}

	w.closed = true
	return
}
