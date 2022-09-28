package handshake

import (
	"bytes"
	"crypto/rand"
	//"crypto/tls"
	//c "crypto"
	"encoding/base64"
    "encoding/gob"
   	"fmt"
	crypto "github.com/lucas-clemente/quic-go/internal/crypto"
)

// ServerConfig is a server config
type ServerConfig struct {
	kex       crypto.KeyExchange
	certChain crypto.CertChain
	ID        []byte
	obit      []byte
}
type MyScfg struct{
	Secret        [32]byte
	Public      [32]byte
	ID        []byte
	Obit      []byte
	//Config 	  tls.Config
	//PrivateKey c.PrivateKey
}
func(s *ServerConfig) GetAttribut()(MyScfg){
	//a:=s.certChain.GetCertChain()
	return MyScfg{
		Secret:		s.kex.SecretKey(),
		Public:		s.kex.Publicckey(),
		ID:			s.ID,
		Obit:		s.obit,  
		//Config:		a,
		//PrivateKey: a.Certificates[0].PrivateKey,
	}
}
func (s *ServerConfig) ToGOB64(m MyScfg) string {
    b := bytes.Buffer{}
    e := gob.NewEncoder(&b)
    err := e.Encode(m)
    if err != nil { fmt.Println(`failed gob Encode`, err) }
    return base64.StdEncoding.EncodeToString(b.Bytes())
}

// go binary decoder
func (s *ServerConfig) FromGOB64(str string) MyScfg {
    m := MyScfg{}
    by, err := base64.StdEncoding.DecodeString(str)
    if err != nil { fmt.Println(`failed base64 Decode`, err); }
    b := bytes.Buffer{}
    b.Write(by)
    d := gob.NewDecoder(&b)
    err = d.Decode(&m)
    if err != nil { fmt.Println(`failed gob Decode`, err); }
    return m
}

// NewServerConfig creates a new server config
func NewServerConfig(kex crypto.KeyExchange, certChain crypto.CertChain) (*ServerConfig, error) {
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		return nil, err
	}

	obit := make([]byte, 8)
	if _, err = rand.Read(obit); err != nil {
		return nil, err
	}

	return &ServerConfig{
		kex:       kex,
		certChain: certChain,
		ID:        id,
		obit:      obit,
	}, nil
}

// Get the server config binary representation
func (s *ServerConfig) Get() []byte {
	var serverConfig bytes.Buffer
	msg := HandshakeMessage{
		Tag: TagSCFG,
		Data: map[Tag][]byte{
			TagSCID: s.ID,
			TagKEXS: []byte("C255"),
			TagAEAD: []byte("AESG"),
			TagPUBS: append([]byte{0x20, 0x00, 0x00}, s.kex.PublicKey()...),
			TagOBIT: s.obit,
			TagEXPY: {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
	}
	msg.Write(&serverConfig)
	return serverConfig.Bytes()
}

// Sign the server config and CHLO with the server's keyData
func (s *ServerConfig) Sign(sni string, chlo []byte) ([]byte, error) {
	return s.certChain.SignServerProof(sni, chlo, s.Get())
}

// GetCertsCompressed returns the certificate data
func (s *ServerConfig) GetCertsCompressed(sni string, commonSetHashes, compressedHashes []byte) ([]byte, error) {
	return s.certChain.GetCertsCompressed(sni, commonSetHashes, compressedHashes)
}
