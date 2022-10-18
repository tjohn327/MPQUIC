package quic

import (
	"net"
	"sync"
	"bytes"
	"encoding/gob"
	"fmt"
	
)

type connection interface {
	Write([]byte) error
	Read([]byte) (int, net.Addr, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetCurrentRemoteAddr(net.Addr)
	GetPconn() net.PacketConn
	Encode() map[string]bytes.Buffer
	
}

type conn struct {
	mutex sync.RWMutex

	pconn       net.PacketConn 
	currentAddr net.Addr
}


var _ connection = &conn{}

func ToEncode(e interface{}) bytes.Buffer {
	var network bytes.Buffer        // Stand-in for a network connection
	enc := gob.NewEncoder(&network)
	err := enc.Encode(e)
	if err != nil {
		fmt.Println("encode error: ",err)
	}
	return network

}
func (c *conn) Encode() map[string]bytes.Buffer {
	var buf = make(map[string]bytes.Buffer)
	//buf["mutex"] = ToEncode(c.mutex)
	buf["pconn"] = ToEncode(c.pconn)
	buf["currentAddr"] = ToEncode(c.currentAddr)

	return buf
}

/*func (c *conn) Decode(network bytes.Buffer) {
	    
	dec := gob.NewDecoder(&network)
	err := dec.Decode(c)
	if err != nil {
		panic("decode error")
	}	
}*/




func (c *conn) GetPconn() net.PacketConn  {
	//fmt.Printf(" \n --conf fd: %+v\n", c.pconn.GetFd())
	return c.pconn
}

func (c *conn) Write(p []byte) error {
	_, err := c.pconn.WriteTo(p, c.currentAddr)
	return err
}

func (c *conn) Read(p []byte) (int, net.Addr, error) {
	return c.pconn.ReadFrom(p)
}

func (c *conn) SetCurrentRemoteAddr(addr net.Addr) {
	c.mutex.Lock()
	c.currentAddr = addr
	c.mutex.Unlock()
}

func (c *conn) LocalAddr() net.Addr {
	return c.pconn.LocalAddr()
}



func (c *conn) RemoteAddr() net.Addr {
	c.mutex.RLock()
	addr := c.currentAddr
	c.mutex.RUnlock()
	return addr
}

func (c *conn) Close() error {
	return c.pconn.Close()
}
