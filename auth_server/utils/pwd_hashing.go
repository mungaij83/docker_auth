package utils

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cesanta/glog"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"math/rand"
	"strings"
)

// MCF formats https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
// Defines representation of various data
const (
	Pbkdf2Sha1   = "pbkdf2"
	Pbkdf2Sha256 = "PBKDF2_SHA256"
	Pbkdf2Sha384 = "PBKDF2_SHA384"
	Pbkdf2Sha512 = "PBKDF2_SHA512"
	Sha256       = "5"
)

type HashValidator func(parameters HashParameters, pwd string) bool
type HashCompute func(parameters HashParameters, pwd string) string

type HashParameters struct {
	HashFunction string `json:"hash_function"`
	RawPassword  string `json:"-"`
	Cost         int64  `json:"cost"`
	SaltLength   int
	Salt         string `json:"salt"`
	Digest       string `json:"digest"`
	Options      StringMap
	MsfOptions   bool // represent options in msf, if not, only cost is added to options
	KeyLength    int
	Validating   bool
	Validator    HashValidator `json:"-"`
	Compute      HashCompute   `json:"-"`
}

// Create hash function
func NewHashParameters(validating bool, fnName string, hsh string) (HashParameters, error) {
	var err error
	h := HashParameters{Validating: validating, HashFunction: fnName, KeyLength: 32, Options: StringMap{}, MsfOptions: false}
	if validating {
		err = h.ParseHash(hsh)
	} else {
		switch fnName {
		case Pbkdf2Sha384, Pbkdf2Sha512, Pbkdf2Sha256, Pbkdf2Sha1:
			h.Compute = HashPbkdf2
			h.Validator = ValidatePbkdf2Hash
			break
		case Sha256:
			break
		default:
			if len(fnName) > 0 {
				err = fmt.Errorf("invalida hashing algorithm: %v", fnName)
			}
		}
	}
	return h, err
}

// Encode JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) (string, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	ss, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return "", err
	}
	return string(ss), nil
}

// Generate cryptographic random string
func (h HashParameters) RandomString(size int) (string, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return "", err
	}
	return EncodeSegment(b), nil
}

// Implements modular crypt format(MCF) to encode key parameters
// $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
// where
// 	1. id: an identifier representing the hashing algorithm (such as 1 for MD5, 5 for SHA-256 etc.)
// 	2. param name and its value: hash complexity parameters, like rounds/iterations count
// 	3. salt: Base64-like encoded salt
// 	4. hash: Base64-like encoded result of hashing the password and salt
func (h HashParameters) Encode() string {
	sf := make([]string, 0)
	// Opening
	sf = append(sf, "")
	// 1. Hash id
	sf = append(sf, h.HashFunction)
	// 2. Add options
	sf = append(sf, h.EncodeOptions())
	// 3. Encode digest password
	if h.Validating {
		if len(h.Salt) > 0 {
			sf = append(sf, h.Salt)
		}
		sf = append(sf, h.Digest)
	} else {
		h.Salt, _ = h.RandomString(h.SaltLength)
		sf = append(sf, h.Salt)
		h.Digest = h.Compute(h, h.RawPassword)
		sf = append(sf, h.Digest)
	}
	// Closing
	sf = append(sf, "")
	final := strings.Join(sf, "$")

	return final
}

func (h HashParameters) EncodeOptions() string {
	if !h.MsfOptions {
		return fmt.Sprintf("%v", h.Cost)
	}
	// Cost
	if h.Cost > 0 {
		h.Options.Add("c", h.Cost)
	}
	// Key length
	if h.KeyLength > 0 {
		h.Options.Add("kl", h.KeyLength)
	}
	values := make([]string, 0)
	for k, v := range h.Options {
		values = append(values, fmt.Sprintf("%v=%v", k, v))
	}

	return strings.Join(values, ",")
}

// Options can be the cost string or standard MSF options
func (h *HashParameters) DecodeHashOptions(opt string) error {
	if !strings.Contains(opt, "=") {
		h.Options.Add("c", opt)
	} else {
		dt := strings.Split(opt, ",")
		for _, op := range dt {
			tm := strings.Split(op, "=")
			if len(tm) == 2 {
				h.Options.Add(tm[0], tm[1])
			} else {
				return fmt.Errorf("invalid option value: %v", op)
			}
		}
	}
	h.Cost = h.Options.GetInt64("c")
	h.KeyLength = int(h.Options.GetInt64("kl"))
	return nil
}

func (h *HashParameters) ParseHash(i string) (err error) {
	if len(strings.TrimSpace(i)) == 0 {
		return errors.New("hash cannot be empty")
	}
	sf := strings.Split(strings.Trim(i, "$"), "$")
	alg := sf[0]

	switch alg {
	case Pbkdf2Sha256, Pbkdf2Sha384, Pbkdf2Sha512:
		if len(sf) != 4 {
			err = fmt.Errorf("invalid pbkdf2 formated hash: %s", alg)
			return
		}
		err = h.DecodeHashOptions(sf[1])
		h.Validator = ValidatePbkdf2Hash
		h.Compute = HashPbkdf2
		h.Salt = sf[2]
		h.Digest = sf[3]
		break
	case Sha256:
		if len(sf) != 3 {
			return fmt.Errorf("invalid hash")
		}
		h.Salt = sf[1]
		h.Digest = sf[2]

		fmt.Printf("Salf: %v\n", h.Salt)
		fmt.Printf("Digest: %v\n", h.Digest)
		break
	default:
		err = fmt.Errorf("unsuppoerted hash function: %v", alg)
	}
	h.HashFunction = alg
	return
}

func (h HashParameters) ValidateHash(pwd string) bool {
	if h.Validator != nil {
		return h.Validator(h, pwd)
	} else {
		panic("hash validator function is not set")
	}
	return false
}

func (h HashParameters) Validate() error {
	var hashOk error
	switch h.HashFunction {
	case Pbkdf2Sha256, Pbkdf2Sha384, Pbkdf2Sha512:
		if h.Cost < 0 {
			hashOk = fmt.Errorf("invalid cost value: %v", h.Cost)
		}
		break
	default:
		hashOk = fmt.Errorf("invalid hash algorithm: %v", h.HashFunction)
	}

	return hashOk
}

func HashPbkdf2(parameters HashParameters, pwd string) string {
	var data [] byte
	switch parameters.HashFunction {
	case Pbkdf2Sha256:
		data = pbkdf2.Key([]byte(pwd), []byte(parameters.Salt), int(parameters.Cost), 32, sha3.New256)
		break
	case Pbkdf2Sha384:
		data = pbkdf2.Key([]byte(pwd), []byte(parameters.Salt), int(parameters.Cost), 32, sha3.New384)
		break
	case Pbkdf2Sha512:
		data = pbkdf2.Key([]byte(pwd), []byte(parameters.Salt), int(parameters.Cost), 32, sha3.New512)
		break
	case Pbkdf2Sha1:
		data = pbkdf2.Key([]byte(pwd), []byte(parameters.Salt), int(parameters.Cost), 32, sha1.New)
		break
	default:
		glog.Infof("invalid hash algorithm to PBKDF2: %v", parameters.HashFunction)
	}
	return EncodeSegment(data)
}

// Compute digest and compare with one in hash
func ValidatePbkdf2Hash(parameters HashParameters, pwd string) bool {

	// check base 64
	_, err := DecodeSegment(parameters.Digest)
	if err != nil {
		glog.Infof("invalid hash digest: %s => %v", parameters.Digest, err)
		return false
	}
	digest := HashPbkdf2(parameters, pwd)

	fmt.Printf("original: %v\n", parameters.Digest)
	fmt.Printf("Calculated: %v\n", digest)

	return strings.Compare(digest, parameters.Digest) == 0
}
