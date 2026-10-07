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

func HashFile(path string) (hash Hash, err error) {
	f, err := os.Open(path)
	if err != nil {
		return hash, err
	}
	defer f.Close()

	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()

	if _, err := io.Copy(io.MultiWriter(md5h, sha1h, sha256h), f); err != nil {
		return hash, err
	}

	hash.MD5 = hex.EncodeToString(md5h.Sum(nil))
	hash.SHA1 = hex.EncodeToString(sha1h.Sum(nil))
	hash.SHA256 = hex.EncodeToString(sha256h.Sum(nil))
	return hash, nil
}
