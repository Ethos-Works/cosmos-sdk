package ethsecp256k1

import (
	"bytes"
	"crypto/ecdsa"
	fmt "fmt"

	errorsmod "cosmossdk.io/errors"
	errortypes "github.com/cosmos/cosmos-sdk/types/errors"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

const (
	// PrivKeySize defines the size of the PrivKey bytes
	PrivKeySize = 32
	// PubKeySize defines the size of the PubKey bytes
	PubKeySize = 33
	// KeyType is the string constant for the EthSecp256k1 algorithm
	KeyType = "eth_secp256k1"
)

// Amino encoding names
const (
	// PrivKeyName defines the amino encoding name for the EthSecp256k1 private key
	PrivKeyName = "ethermint/PrivKeyEthSecp256k1"
	// PubKeyName defines the amino encoding name for the EthSecp256k1 public key
	PubKeyName = "ethermint/PubKeyEthSecp256k1"
)

// ----------------------------------------------------------------------------
// secp256k1 Private Key

var (
	_ cryptotypes.PrivKey  = (*PrivKey)(nil)
	_ codec.AminoMarshaler = (*PrivKey)(nil)
)

// PrivKey defines a type alias for an ecdsa.PrivateKey that implements
// Tendermint's PrivateKey interface.
// type PrivKey struct {
// 	Key []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
// }

// GenerateKey generates a new random private key. It returns an error upon
// failure.
func GenerateKey() (*PrivKey, error) {
	priv, err := ethcrypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	return &PrivKey{Key: ethcrypto.FromECDSA(priv)}, nil
}

// Bytes returns the raw ECDSA private key bytes.
func (privKey PrivKey) Bytes() []byte {
	bz := make([]byte, len(privKey.Key))
	copy(bz, privKey.Key)

	return bz
}

// PubKey returns the ECDSA private key's public key.
func (privKey PrivKey) PubKey() cryptotypes.PubKey {
	ecdsaPrivKey := privKey.ToECDSA()
	return &PubKey{Key: ethcrypto.CompressPubkey(&ecdsaPrivKey.PublicKey)}
}

// Equals returns true if two ECDSA private keys are equal and false otherwise.
func (privkey PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	return bytes.Equal(privkey.Bytes(), other.Bytes())
}

// Type implements crypto.PrivKey.
func (PrivKey) Type() string {
	return KeyType
}

// MarshalAmino overrides Amino binary marshaling.
func (privKey PrivKey) MarshalAmino() ([]byte, error) {
	return privKey.Key, nil
}

// UnmarshalAmino overrides Amino binary marshaling.
func (privKey *PrivKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PrivKeySize {
		return fmt.Errorf("invalid privkey size, expected %d got %d", PrivKeySize, len(bz))
	}
	privKey.Key = bz

	return nil
}

// MarshalAminoJSON overrides Amino JSON marshaling.
func (privKey PrivKey) MarshalAminoJSON() ([]byte, error) {
	// When we marshal to Amino JSON, we don't marshal the "key" field itself,
	// just its contents (i.e. the key bytes).
	return privKey.MarshalAmino()
}

// UnmarshalAminoJSON overrides Amino JSON marshaling.
func (privKey *PrivKey) UnmarshalAminoJSON(bz []byte) error {
	return privKey.UnmarshalAmino(bz)
}

// Sign creates a recoverable ECDSA signature on the secp256k1 curve over the
// Keccak256 hash of the provided message. The produced signature is 65 bytes
// where the last byte contains the recovery ID.
func (privkey PrivKey) Sign(msg []byte) ([]byte, error) {
	return ethcrypto.Sign(ethcrypto.Keccak256Hash(msg).Bytes(), privkey.ToECDSA())
}

// ToECDSA returns the ECDSA private key as a reference to ecdsa.PrivateKey type.
// The function will panic if the private key is invalid.
func (privkey PrivKey) ToECDSA() *ecdsa.PrivateKey {
	key, err := ethcrypto.ToECDSA(privkey.Key)
	if err != nil {
		panic(err)
	}
	return key
}

// ----------------------------------------------------------------------------
// secp256k1 Public Key

var (
	_ cryptotypes.PubKey   = (*PubKey)(nil)
	_ codec.AminoMarshaler = (*PubKey)(nil)
)

// Address returns the address of the ECDSA public key.
// The function will panic if the public key is invalid.
func (key *PubKey) Address() cryptotypes.Address {
	pubk, err := ethcrypto.DecompressPubkey(key.Key)
	if err != nil {
		panic(err)
	}

	return cryptotypes.Address(ethcrypto.PubkeyToAddress(*pubk).Bytes())
}

// Bytes returns the raw bytes of the ECDSA public key.
// The function panics if the key cannot be marshaled to bytes.
func (key *PubKey) Bytes() []byte {
	bz := make([]byte, len(key.Key))
	copy(bz, key.Key)

	return bz
	// bz, err := CryptoCodec.MarshalBinaryBare(key)
	// if err != nil {
	// 	panic(err)
	// }
	// return bz

	// return key.Key
}

// String implements the fmt.Stringer interface.
func (pubKey PubKey) String() string {
	return fmt.Sprintf("EthPubKeySecp256k1{%X}", pubKey.Key)
}

// MarshalAmino overrides Amino binary marshaling.
func (pubKey PubKey) MarshalAmino() ([]byte, error) {
	return pubKey.Key, nil
}

// UnmarshalAmino overrides Amino binary marshaling.
func (pubKey *PubKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PubKeySize {
		return errorsmod.Wrapf(errortypes.ErrInvalidPubKey, "invalid pubkey size, expected %d, got %d", PubKeySize, len(bz))
	}
	pubKey.Key = bz

	return nil
}

// MarshalAminoJSON overrides Amino JSON marshaling.
func (pubKey PubKey) MarshalAminoJSON() ([]byte, error) {
	// When we marshal to Amino JSON, we don't marshal the "key" field itself,
	// just its contents (i.e. the key bytes).
	return pubKey.MarshalAmino()
}

// UnmarshalAminoJSON overrides Amino JSON marshaling.
func (pubKey *PubKey) UnmarshalAminoJSON(bz []byte) error {
	return pubKey.UnmarshalAmino(bz)
}

// Type implements types.PubKey.
func (*PubKey) Type() string {
	return KeyType
}

// Equals returns true if two ECDSA public keys are equal and false otherwise.
func (key *PubKey) Equals(other cryptotypes.PubKey) bool {
	return bytes.Equal(key.Bytes(), other.Bytes())
}

// VerifyBytes verifies that the ECDSA public key created a given signature over
// the provided message. It will calculate the Keccak256 hash of the message
// prior to verification.
func (key *PubKey) VerifySignature(msg []byte, sig []byte) bool {
	if len(sig) == 65 {
		// remove recovery ID if contained in the signature
		sig = sig[:len(sig)-1]
	}

	// the signature needs to be in [R || S] format when provided to VerifySignature
	return secp256k1.VerifySignature(key.Bytes(), ethcrypto.Keccak256Hash(msg).Bytes(), sig)
}
