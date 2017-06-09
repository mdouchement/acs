package acs_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/mdouchement/acs"
)

var (
	key  = []byte("f>Gp@U-y4;$8`C@QP#^s]]ptuN='mD7,")
	data = []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
)

func TestACS(t *testing.T) {
	var unknown bytes.Buffer
	buf := bytes.NewBuffer(data)

	w, err := acs.NewWriter(&unknown, key)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	_, err = io.Copy(w, buf)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if err = w.Close(); err != nil {
		t.Fatalf("Error: %v", err)
	}

	r, err := acs.NewReader(&unknown, key)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	buf.Reset()
	_, err = io.Copy(buf, r)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if !bytes.Equal(data, buf.Bytes()) {
		t.Fatalf("Expected %s, got %s", data, buf.Bytes())
	}
}
