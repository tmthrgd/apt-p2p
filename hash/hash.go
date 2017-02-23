package hash

import (
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

var (
	nameToHash = make(map[string]crypto.Hash, int(crypto.SHA512_256-crypto.MD4)+1)
	hashToName = make(map[crypto.Hash]string, int(crypto.SHA512_256-crypto.MD4)+1)
)

var (
	errParseHashError        = errors.New("invalid hash")
	errInvalidAlgorithmError = errors.New("invalid algorithm")
)

var b64Encoding = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~_").WithPadding(base64.NoPadding)

type Hash struct {
	hash []byte
	alg  crypto.Hash
}

func NewRaw(hash []byte, alg crypto.Hash) *Hash {
	if len(hash) != alg.Size() {
		panic("hash size is not valid for algorithm")
	}

	return &Hash{hash, alg}
}

func New(data []byte, alg crypto.Hash) (*Hash, error) {
	hasher := alg.New()

	if _, err := hasher.Write(data); err != nil {
		return nil, err
	}

	return &Hash{
		hasher.Sum(nil),
		alg,
	}, nil
}

func NewReader(r io.Reader, alg crypto.Hash) (h *Hash, read int64, err error) {
	hasher := alg.New()

	if read, err = io.Copy(hasher, r); err != nil {
		return
	}

	h = &Hash{
		hasher.Sum(nil),
		alg,
	}
	return
}

func NewReaderN(r io.Reader, n int64, alg crypto.Hash) (h *Hash, read int64, err error) {
	hasher := alg.New()

	if read, err = io.CopyN(hasher, r, n); err != nil {
		return
	}

	h = &Hash{
		hasher.Sum(nil),
		alg,
	}
	return
}

func Parse(s string) (*Hash, error) {
	idx := strings.LastIndex(s, "-")
	if len(s) == 0 || idx <= 0 || idx+1 >= len(s)-1 {
		return nil, errParseHashError
	}

	alg, ok := nameToHash[strings.ToLower(s[:idx])]
	if !ok || !alg.Available() {
		return nil, errInvalidAlgorithmError
	}

	hashBytes, err := b64Encoding.DecodeString(s[idx+1:])
	if err != nil {
		return nil, err
	}

	if len(hashBytes) != alg.Size() {
		return nil, errParseHashError
	}

	return &Hash{
		hashBytes,
		alg,
	}, nil
}

func (h *Hash) Equal(h2 *Hash) bool {
	return h2 != nil && h.alg == h2.alg && subtle.ConstantTimeCompare(h.hash, h2.hash) == 1
}

func (h *Hash) EqualString(s string) bool {
	h2, err := Parse(s)
	return err == nil && h.Equal(h2)
}

func (h *Hash) EqualData(b []byte) bool {
	h2, err := New(b, h.alg)
	return err == nil && h.Equal(h2)
}

func (h *Hash) EqualHash(hash []byte, alg crypto.Hash) bool {
	h2 := &Hash{hash, alg}
	return h.Equal(h2)
}

func (h *Hash) EqualReader(r io.Reader) (bool, int64) {
	h2, read, err := NewReader(r, h.alg)
	return err == nil && h.Equal(h2), read
}

func (h *Hash) EqualReaderN(r io.Reader, n int64) (bool, int64) {
	h2, read, err := NewReaderN(r, n, h.alg)
	return err == nil && h.Equal(h2), read
}

func (h *Hash) HashAlgorithm() crypto.Hash {
	return h.alg
}

func (h *Hash) Hasher() hash.Hash {
	return h.alg.New()
}

func (h *Hash) HashSize() int {
	return h.alg.Size()
}

func (h *Hash) HashAvailable() bool {
	return h.alg.Available()
}

func (h *Hash) HashBytes() []byte {
	return append([]byte(nil), h.hash...)
}

func (h *Hash) String() string {
	return hashToName[h.alg] + "-" + b64Encoding.EncodeToString(h.hash)
}

var _ fmt.Stringer = (*Hash)(nil)

func init() {
	for i, name := range [...]string{
		"md4",              // import golang.org/x/crypto/md4
		"md5",              // import crypto/md5
		"sha1",             // import crypto/sha1
		"sha224", "sha256", // import crypto/sha256
		"sha384", "sha512", // import crypto/sha512
		"",                                             // no implementation; MD5+SHA1 used for TLS RSA
		"ripemd160",                                    // import golang.org/x/crypto/ripemd160
		"sha3-224", "sha3-256", "sha3-384", "sha3-512", // import golang.org/x/crypto/sha3
		"sha512-224", "sha512-256", // import crypto/sha512
	} {
		if len(name) == 0 {
			continue
		}

		hash := crypto.Hash(i) + crypto.MD4
		nameToHash[name] = hash
		hashToName[hash] = name
	}

	nameToHash["sha"] = crypto.SHA1

	for i, name := range [...]string{"sha-224", "sha-256", "sha-384", "sha-512"} {
		nameToHash[name] = crypto.Hash(i) + crypto.SHA224
	}

	for i, size := range [...]string{"224", "256"} {
		hash := crypto.Hash(i) + crypto.SHA512_224
		nameToHash["sha512:"+size] = hash
		nameToHash["sha-512:"+size] = hash
		nameToHash["sha-512-"+size] = hash
		nameToHash["sha-512/"+size] = hash
	}

	for i, name := range [...]string{"sha3:224", "sha3:256", "sha3:384", "sha3:512"} {
		nameToHash[name] = crypto.Hash(i) + crypto.SHA3_224
	}
}
