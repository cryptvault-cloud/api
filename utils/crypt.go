package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"math/big"
	"slices"
	"strings"
	"time"

	b64 "encoding/base64"
)

const (
	// curveP521 is the only curve this package generates keys for. The curve
	// name also selects the hash used by encrypt/decrypt, so it is part of the
	// wire format.
	curveP521 = "P-521"

	jwtType = "JWT"
	jwtAlg  = curveP521

	// macLen is the length sumTag truncates the HMAC-SHA512 tag to.
	macLen = 16
)

func GenerateNewKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return private, &private.PublicKey, nil
}

func GetPrivateKeyFromB64String(key string) (*ecdsa.PrivateKey, error) {
	privateKeyPem, err := b64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	return DecodePrivateKey(string(privateKeyPem))
}

func GetPublicKeyFromB64String(key string) (*ecdsa.PublicKey, error) {
	publicKeyPem, err := b64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	return DecodePublicKey(string(publicKeyPem))
}

func GetB64FromPrivateKey(key *ecdsa.PrivateKey) (string, error) {
	pem, err := EncodePrivateKey(key)
	if err != nil {
		return "", err
	}
	return b64.StdEncoding.EncodeToString([]byte(pem)), nil
}

func GetB64FromPublicKey(key *ecdsa.PublicKey) (string, error) {
	pem, err := EncodePublicKey(key)
	if err != nil {
		return "", err
	}
	return b64.StdEncoding.EncodeToString([]byte(pem)), nil
}

func EncodePublicKey(publicKey *ecdsa.PublicKey) (string, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncodedPub), nil
}

func EncodePrivateKey(privateKey *ecdsa.PrivateKey) (string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded), nil
}

func Encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string, error) {
	pemEncodedPriv, err := EncodePrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	pemEncodedPub, err := EncodePublicKey(publicKey)
	if err != nil {
		return "", "", err
	}

	return pemEncodedPriv, pemEncodedPub, nil
}

func Decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := DecodePrivateKey(pemEncoded)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := DecodePublicKey(pemEncodedPub)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func DecodePrivateKey(pemEncoded string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, fmt.Errorf("unable to decode pem")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func DecodePublicKey(pemEncodedPub string) (*ecdsa.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	if blockPub == nil {
		return nil, fmt.Errorf("unable to decode pem")
	}
	genericPublicKey, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, err
	}
	res, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("casting into *ecdsa.PublicKey failed")
	}
	return res, nil
}

func Sign(privatekey *ecdsa.PrivateKey, message string) (string, error) {
	signhash := sha256.Sum256([]byte(message))

	r, s, err := ecdsa.Sign(rand.Reader, privatekey, signhash[:])
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", b64.StdEncoding.EncodeToString(r.Bytes()), b64.StdEncoding.EncodeToString(s.Bytes())), nil
}

func Verify(pubkey *ecdsa.PublicKey, message, signature string) (bool, error) {
	rPart, sPart, found := strings.Cut(signature, "-")
	if !found || strings.Contains(sPart, "-") {
		return false, fmt.Errorf("error split signature get not exactly a list with two elements got %s ", signature)
	}
	rb, err := b64.StdEncoding.DecodeString(rPart)
	if err != nil {
		return false, err
	}
	sb, err := b64.StdEncoding.DecodeString(sPart)
	if err != nil {
		return false, err
	}

	signhash := sha256.Sum256([]byte(message))

	return ecdsa.Verify(pubkey, signhash[:], new(big.Int).SetBytes(rb), new(big.Int).SetBytes(sb)), nil
}

type Message struct {
	Expired  time.Time `json:"exp,omitempty"`
	IssuedAt time.Time `json:"iat,omitempty"`
	VaultId  string    `json:"vault_id,omitempty"`
	TokenId  string    `json:"token_id,omitempty"`
}

type SignCreatorMessage struct {
	IssuedAt       time.Time `json:"iat,omitempty"`
	VaultId        string    `json:"vault_id,omitempty"`
	CreatorTokenId string    `json:"creator_token_id,omitempty"`
	TokenId        string    `json:"token_id,omitempty"`
}

type JwtHeader struct {
	Type      string `json:"typ,omitempty"`
	Algorithm string `json:"alg,omitempty"`
}

// encodedJWTHeader is the base64 of {"typ":"JWT","alg":"P-521"}. Every token
// this package issues starts with it, so it is pinned by a test.
var encodedJWTHeader = encodeJWTHeader()

func encodeJWTHeader() string {
	// a struct of two strings cannot fail to marshal
	res, _ := json.Marshal(JwtHeader{
		Type:      jwtType,
		Algorithm: jwtAlg,
	})

	return b64.StdEncoding.EncodeToString(res)
}

func GetIdFromPublicKey(publicKey *ecdsa.PublicKey, vaultId string) (string, error) {
	encodeKey, err := EncodePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	b64pem := b64.StdEncoding.EncodeToString([]byte(encodeKey))
	h := sha256.New()
	_, err = h.Write([]byte(vaultId))
	if err != nil {
		return "", err
	}
	_, err = h.Write([]byte(b64pem))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func SignCreatorJWT(private *ecdsa.PrivateKey, childTokenId, vaultId string) (string, error) {
	tokenID, err := GetIdFromPublicKey(&private.PublicKey, vaultId)
	if err != nil {
		return "", err
	}
	return signJWT(private, SignCreatorMessage{
		IssuedAt:       time.Now(),
		VaultId:        vaultId,
		CreatorTokenId: tokenID,
		TokenId:        childTokenId,
	})
}

func SignJWT(private *ecdsa.PrivateKey, vaultId string) (string, error) {
	tokenID, err := GetIdFromPublicKey(&private.PublicKey, vaultId)
	if err != nil {
		return "", err
	}
	return signJWT(private, Message{
		Expired:  time.Now().Add(5 * time.Minute),
		IssuedAt: time.Now(),
		VaultId:  vaultId,
		TokenId:  tokenID,
	})
}

func DecodeCreatorJWT(jwt string) (*SignCreatorMessage, string, error) {
	return decodeJWT[SignCreatorMessage](jwt)
}

func DecodeJWT(jwt string) (*Message, string, error) {
	return decodeJWT[Message](jwt)
}

func VerifyCreatorJWT(pubkey *ecdsa.PublicKey, jwt string) (*SignCreatorMessage, error) {
	return verifyJWT[SignCreatorMessage](pubkey, jwt, nil)
}

func VerifyJWT(pubkey *ecdsa.PublicKey, jwt string) (*Message, error) {
	return verifyJWT(pubkey, jwt, func(message *Message) error {
		if !time.Now().Before(message.Expired) {
			return fmt.Errorf("token is expired")
		}
		return nil
	})
}

// signJWT builds a <header>.<payload>.<signature> token for the given claims.
func signJWT(private *ecdsa.PrivateKey, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	sign, err := Sign(private, string(payload))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", encodedJWTHeader, b64.StdEncoding.EncodeToString(payload), sign), nil
}

func splitJWT(jwt string) ([]string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("JWT invalid part size")
	}
	return parts, nil
}

// decodeJWT validates the header and unmarshals the claims into T. It returns
// the claims together with the raw payload json, which is what the signature
// is made over.
func decodeJWT[T any](jwt string) (*T, string, error) {
	parts, err := splitJWT(jwt)
	if err != nil {
		return nil, "", err
	}

	headerjson, err := b64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", err
	}
	var header JwtHeader
	if err := json.Unmarshal(headerjson, &header); err != nil {
		return nil, "", err
	}
	if header.Algorithm != jwtAlg {
		return nil, "", fmt.Errorf("invalid Alg")
	}
	if header.Type != jwtType {
		return nil, "", fmt.Errorf("invalid Type")
	}

	messagejson, err := b64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", err
	}
	var message T
	if err := json.Unmarshal(messagejson, &message); err != nil {
		return nil, "", err
	}

	return &message, string(messagejson), nil
}

// verifyJWT decodes the token, runs the optional claim validation and checks
// that the signature was made by the matching private key.
func verifyJWT[T any](pubkey *ecdsa.PublicKey, jwt string, validate func(*T) error) (*T, error) {
	parts, err := splitJWT(jwt)
	if err != nil {
		return nil, err
	}

	message, messagejson, err := decodeJWT[T](jwt)
	if err != nil {
		return nil, err
	}

	if validate != nil {
		if err := validate(message); err != nil {
			return nil, err
		}
	}

	// Verify reports a wrong but well formed signature as (false, nil), so the
	// result has to be checked on top of the error.
	valid, err := Verify(pubkey, messagejson, parts[2])
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("invalid signature")
	}

	return message, nil
}

func Encrypt(pubkey *ecdsa.PublicKey, message string) ([]byte, error) {
	res, err := encrypt(rand.Reader, pubkey, []byte(message), nil, nil)
	if err != nil {
		return nil, err
	}
	return []byte(b64.StdEncoding.EncodeToString(res)), nil
}

func Decrypt(private *ecdsa.PrivateKey, message string) ([]byte, error) {
	passframe, err := b64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil, err
	}
	return decrypt(private, passframe, nil, nil)
}

// cipherSuite returns the hash and the symmetric key size used for a curve.
// Both are part of the wire format and must not change.
func cipherSuite(curveName string) (newHash func() hash.Hash, keySize int) {
	newHash = sha256.New
	if curveName == curveP521 {
		newHash = sha512.New
	}
	return newHash, newHash().Size() / 2
}

// deriveKeys splits the KDF output of the shared secret into the symmetric
// encryption key and the MAC key.
func deriveKeys(newHash func() hash.Hash, shared, s1 []byte, keySize int) (ke, km []byte) {
	h := newHash()

	K := kdf(h, shared, s1)
	ke, km = K[:keySize], K[keySize:]

	if len(km) < 32 {
		h.Write(km)
		km = h.Sum(nil)
	}

	return ke, km
}

// sharedSecretCandidates returns the shared secret in the form used by clients
// from before the crypto/ecdh migration first - those derived the keys from a
// big.Int, which dropped leading zero bytes - followed by the raw secret when
// the two differ.
func sharedSecretCandidates(shared []byte) [][]byte {
	legacy := bytes.TrimLeft(shared, "\x00")
	if len(legacy) == len(shared) {
		return [][]byte{shared}
	}
	return [][]byte{legacy, shared}
}

func encrypt(rand io.Reader, public *ecdsa.PublicKey, in, s1, s2 []byte) ([]byte, error) {
	newHash, keySize := cipherSuite(public.Curve.Params().Name)

	recipientPub, err := public.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	ephPriv, err := recipientPub.Curve().GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	shared, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return nil, err
	}

	ke, km := deriveKeys(newHash, shared, s1, keySize)

	c := encryptSymmetric(rand, in, ke)
	tag := sumTag(c, s2, to32ByteArray(km))

	// <ephemeral public key> || <ciphertext> || <tag>
	return slices.Concat(ephPriv.PublicKey().Bytes(), c, tag[:]), nil
}

func decrypt(private *ecdsa.PrivateKey, in, s1, s2 []byte) ([]byte, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("invalid message")
	}
	if in[0] != 2 && in[0] != 3 && in[0] != 4 {
		return nil, fmt.Errorf("invalid public key")
	}

	params := private.Params()
	newHash, keySize := cipherSuite(params.Name)

	// uncompressed point: 0x04 || X || Y
	messageStart := 1 + 2*((params.BitSize+7)/8)
	// the ciphertext carries at least the AES-CTR nonce
	if len(in) < messageStart+aes.BlockSize+macLen {
		return nil, fmt.Errorf("invalid message")
	}
	messageEnd := len(in) - macLen

	privECDH, err := private.ECDH()
	if err != nil {
		return nil, err
	}

	Rpub, err := privECDH.Curve().NewPublicKey(in[:messageStart])
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	shared, err := privECDH.ECDH(Rpub)
	if err != nil {
		return nil, err
	}

	ciphertext := in[messageStart:messageEnd]
	mac := in[messageEnd:]

	for _, candidate := range sharedSecretCandidates(shared) {
		ke, km := deriveKeys(newHash, candidate, s1, keySize)
		if verifyTag(to16ByteArray(mac), ciphertext, s2, to32ByteArray(km)) {
			return decryptSymmetric(ciphertext, ke), nil
		}
	}

	return nil, fmt.Errorf("message tags don't match")
}
