package crypto

// KeyExchange manages the exchange of keys
type KeyExchange interface {
	SecretKey() [32]byte
	PublicKey() []byte
	Publicckey() [32]byte
	CalculateSharedKey(otherPublic []byte) ([]byte, error)
}
