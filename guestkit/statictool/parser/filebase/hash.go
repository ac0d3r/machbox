package filebase

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

type Hash struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

func HashFile(path string) (Hash, error) {
	f, err := os.Open(path)
	if err != nil {
		return Hash{}, err
	}
	defer f.Close()
	return hashReader(f)
}

func hashReader(r io.Reader) (Hash, error) {
	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()

	if _, err := io.Copy(io.MultiWriter(md5h, sha1h, sha256h), r); err != nil {
		return Hash{}, err
	}

	return Hash{
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
	}, nil
}
