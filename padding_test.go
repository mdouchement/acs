package acs_test

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/mdouchement/acs"
)

var fixtures = []struct {
	data   []byte
	padded []byte
}{
	{[]byte("XC8KM8KA8JM8WX8GA8HZ8FV8FZ8PL8H98QX8PF8AP8ZA8JP8LK8HC8PG8ZP"), append([]byte("XC8KM8KA8JM8WX8GA8HZ8FV8FZ8PL8H98QX8PF8AP8ZA8JP8LK8HC8PG8ZP"), 5, 5, 5, 5, 5)},
	{[]byte("XC8KM8KA8JM8WX8GA8HZ8FV8FZ8PL8H98QX8PF8AP8ZA8JP8LK8HC8PG8Z"), append([]byte("XC8KM8KA8JM8WX8GA8HZ8FV8FZ8PL8H98QX8PF8AP8ZA8JP8LK8HC8PG8Z"), 6, 6, 6, 6, 6, 6)},
}

func TestIsValidPKCS5Padding(t *testing.T) {
	// Good
	for _, f := range fixtures {
		if !acs.IsValidPKCS5Padding(f.padded, aes.BlockSize) {
			t.Fatalf("Expected %v, got %v", true, false)
		}
	}

	// Bad

	// data's length must be a multiple of blockSize
	padded := append([]byte("XC8KM8KA8JM8WX8GA8HZ8FV8FZ8PL8H98QX8PF8AP8ZA8JP8LK8HC8PG8ZP"), 5, 5, 5, 5)
	if acs.IsValidPKCS5Padding(padded, aes.BlockSize) {
		t.Fatalf("Expected %v, got %v", false, true)
	}

	// Padding value is always present at the end of the data and is included in ]0;blockSize]
	padded = append([]byte("XC8KM8KA8JM8WX8GA8HZ8FV8FZ8PL8H98QX8PF8AP8ZA8JP8LK8HC8PG8ZP"), 0, 0, 0, 0, 0)
	if acs.IsValidPKCS5Padding(padded, aes.BlockSize) {
		t.Fatalf("Expected %v, got %v", false, true)
	}

	padded = append([]byte("XC8KM8KA8JM8WX8GA8HZ8FV8FZ8PL8H98QX8PF8AP8ZA8JP8LK8HC8PG8ZP"), 17, 17, 17, 17, 17)
	if acs.IsValidPKCS5Padding(padded, aes.BlockSize) {
		t.Fatalf("Expected %v, got %v", false, true)
	}

	// Padding value is the lentgh of the padded data
	padded = append([]byte("XC8KM8KA8JM8WX8GA8HZ8FV8FZ8PL8H98QX8PF8AP8ZA8JP8LK8HC8PG8ZP"), 42, 5, 5, 5, 5)
	if acs.IsValidPKCS5Padding(padded, aes.BlockSize) {
		t.Fatalf("Expected %v, got %v", false, true)
	}
}

func TestPKCS5Padding(t *testing.T) {
	for _, f := range fixtures {
		padded := acs.PKCS5Padding(f.data, aes.BlockSize)

		if !bytes.Equal(f.padded, padded) {
			t.Fatalf("Expected %v, got %v", f.padded, padded)
		}
	}
}

func TestPKCS5UnPadding(t *testing.T) {
	for _, f := range fixtures {
		unpadded := acs.PKCS5UnPadding(f.padded)

		if !bytes.Equal(f.data, unpadded) {
			t.Fatalf("Expected %v, got %v", f.data, unpadded)
		}
	}
}
