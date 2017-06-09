# ACS - AES CBC Streamer

[![CircleCI](https://circleci.com/gh/mdouchement/acs.svg?style=shield)](https://circleci.com/gh/mdouchement/acs)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/mdouchement/acs)
[![Go Report Card](https://goreportcard.com/badge/github.com/mdouchement/acs)](https://goreportcard.com/report/github.com/mdouchement/acs)
[![License](https://img.shields.io/github/license/mdouchement/acs.svg)](http://opensource.org/licenses/MIT)

ACS is a simple Golang library that provides AES-CBC Writer and Reader.

```go
key := []byte("f>Gp@U-y4;$8`C@QP#^s]]ptuN='mD7,")

w, err := acs.NewWriter(anIoWriter, key)
if err != nil {
  // Something
}
io.Copy(w, anIoReader)



r, err := acs.NewReader(anIoReader, key)
if err != nil {
  // Something
}
io.Copy(anIoWriter, r)
```


## License

**MIT**


## Contributing

All PRs are welcome.

1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
5. Push to the branch (git push origin my-new-feature)
6. Create new Pull Request
