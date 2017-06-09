package acs

import (
	"bytes"
)

// IsValidPKCS5Padding checks whether or not the padding is valid.
func IsValidPKCS5Padding(data []byte, blockSize int) bool {
	length := len(data)
	unpadding := int(data[length-1])

	if length%blockSize > 0 {
		// data's length must be a multiple of blockSize.
		return false
	}

	if unpadding < 1 || unpadding > blockSize {
		// Padding value is always present at the end of the data and is included in ]0;blockSize]
		return false
	}

	// Padding value is the lentgh of the padded data.
	for _, p := range data[(length - unpadding):] {
		if int(p) != unpadding {
			return false
		}
	}

	return true
}

// PKCS5Padding adds padding to the given data according to the blockSize.
func PKCS5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS5UnPadding removes padding from the given data.
func PKCS5UnPadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
