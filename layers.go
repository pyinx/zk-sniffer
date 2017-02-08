package main

import (
	// "encoding/binary"
	// "errors"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// LayerTypeZKConReq  = gopacket.RegisterLayerType(2001, gopacket.LayerTypeMetadata{Name: "ZKConReq", Decoder: gopacket.DecodeFunc(decodeZKConReq)})
	// LayerTypeZKConResp = gopacket.RegisterLayerType(2002, gopacket.LayerTypeMetadata{Name: "ZKConResp", Decoder: gopacket.DecodeFunc(decodeZKConResp)})
	LayerTypeZKReq  = gopacket.RegisterLayerType(2003, gopacket.LayerTypeMetadata{Name: "ZKReq", Decoder: gopacket.DecodeFunc(decodeZKReq)})
	LayerTypeZKResp = gopacket.RegisterLayerType(2004, gopacket.LayerTypeMetadata{Name: "ZKResp", Decoder: gopacket.DecodeFunc(decodeZKResp)})
)

// type ZKConReq struct {
// 	layers.BaseLayer

// 	ProtocolVersion int32
// 	LastZxidSeen    int64
// 	TimeOut         int32
// 	SessionID       int64
// 	Passwd          []byte
// }

// func (z *ZKConReq) LayerType() gopacket.LayerType {
// 	return LayerTypeZKConReq
// }

// func decodeZKConReq(data []byte, p gopacket.PacketBuilder) error {
// 	log.Println("start decode zk con req packet")
// 	z := &ZKConReq{}
// 	err := z.DecodeFromBytes(data, p)
// 	if err != nil {
// 		return err
// 	}
// 	log.Printf("decode req con strcut: %#v\n", z)
// 	p.AddLayer(z)
// 	p.SetApplicationLayer(z)
// 	return nil
// }

// func (z *ZKConReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
// 	if len(data) < 28 {
// 		return ErrShortBuffer
// 	}
// 	// z.BaseLayer = layers.BaseLayer{Contents: data[:]}
// 	z.ProtocolVersion = BytesToInt32(data[4:8])
// 	z.LastZxidSeen = BytesToInt64(data[8:16])
// 	z.TimeOut = BytesToInt32(data[16:20])
// 	z.SessionID = BytesToInt64(data[20:28])
// 	passLen := BytesToInt32(data[28:])
// 	if passLen != 16 {
// 		return ErrUnknownPacket
// 	}
// 	z.Passwd = data[28 : 28+passLen]
// 	return nil
// }

// func (z *ZKConReq) CanDecode() gopacket.LayerClass {
// 	return LayerTypeZKConReq
// }

// func (z *ZKConReq) NextLayerType() gopacket.LayerType {
// 	return gopacket.LayerTypePayload
// }

// func (z *ZKConReq) Payload() []byte {
// 	return nil
// }

// type ZKConResp struct {
// 	layers.BaseLayer

// 	ProtocolVersion int32
// 	TimeOut         int32
// 	SessionID       int64
// 	Passwd          []byte
// }

// func (z *ZKConResp) LayerType() gopacket.LayerType {
// 	return LayerTypeZKConResp
// }

// func decodeZKConResp(data []byte, p gopacket.PacketBuilder) error {
// 	log.Println("start decode zk con resp packet")
// 	z := &ZKConResp{}
// 	err := z.DecodeFromBytes(data, p)
// 	if err != nil {
// 		return err
// 	}
// 	log.Printf("decode resp con strcut: %#v\n", z)
// 	p.AddLayer(z)
// 	p.SetApplicationLayer(z)
// 	return nil
// }

// func (z *ZKConResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
// 	if len(data) < 20 {
// 		return ErrShortBuffer
// 	}
// 	// z.BaseLayer = layers.BaseLayer{Contents: data[:]}
// 	z.ProtocolVersion = BytesToInt32(data[4:8])
// 	z.TimeOut = BytesToInt32(data[8:12])
// 	z.SessionID = BytesToInt64(data[12:20])
// 	passLen := BytesToInt32(data[20:])
// 	if passLen != 16 {
// 		return ErrUnknownPacket
// 	}
// 	z.Passwd = data[20 : 20+passLen]
// 	return nil
// }

// func (z *ZKConResp) CanDecode() gopacket.LayerClass {
// 	return LayerTypeZKConResp
// }

// func (z *ZKConResp) NextLayerType() gopacket.LayerType {
// 	return gopacket.LayerTypePayload
// }

// func (z *ZKConResp) Payload() []byte {
// 	return nil
// }

type ZKReq struct {
	layers.BaseLayer

	Xid    int32
	Opcode int32
	Path   string
	Data   []byte
	Acl    []ACL
	flags  int32

	Optype string
}

func (z *ZKReq) LayerType() gopacket.LayerType {
	return LayerTypeZKReq
}

func decodeZKReq(data []byte, p gopacket.PacketBuilder) error {
	z := &ZKReq{}
	err := z.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(z)
	p.SetApplicationLayer(z)
	return nil
}

func (z *ZKReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 12 {
		return ErrShortBuffer
	}
	// z.BaseLayer = layers.BaseLayer{Contents: data[:]}
	z.Xid = BytesToInt32(data[4:8])
	z.Opcode = BytesToInt32(data[8:12])
	switch z.Opcode {
	case 0: //CONNECT
		z.Optype = "CONNECT"
	case 1: //CREATE
		z.Optype = "CREATE"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
		dataLen := BytesToInt32(data[n : n+4])
		n = n + 4
		z.Data = data[n : n+dataLen]
	case 2: //DELETE
		z.Optype = "DELETE"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case 3: //EXISTS
		z.Optype = "EXISTS"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case 4: //GETDATA
		z.Optype = "GETDATA"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case 5: //SETDATA
		z.Optype = "SETDATA"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
		dataLen := BytesToInt32(data[n : n+4])
		n = n + 4
		z.Data = data[n : n+dataLen]
	case 6: //GETACL
		z.Optype = "GETACL"
	case 7: //SETACL
		z.Optype = "SETACL"
	case 8: //GETCHILDREN
		z.Optype = "GETCHILDREN"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case 9: //SYNC
		z.Optype = "SYNC"
	case 11: //PING
		z.Optype = "PING"
	case 12: //GETCHILDREN2
		z.Optype = "GETCHILDREN2"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case 13: //CHECK
		z.Optype = "CHECK"
	case 14: //MULTI
		z.Optype = "MULTI"
	case 15: //CREATE2
		z.Optype = "CREATE2"
	case 16: //RECONFIG
		z.Optype = "RECONFIG"
	case -10: //CREATESESSION
		z.Optype = "CREATESESSION"
	case -11: //CLOSE
		z.Optype = "CLOSE"
	case 100: //SETAUTH
		z.Optype = "SETAUTH"
	case 101: //SETWATCHES
		z.Optype = "SETWATCHES"
	default:
		log.Printf("Unknown Opcode: %d\n", z.Opcode)
	}
	return nil
}

func (z *ZKReq) CanDecode() gopacket.LayerClass {
	return LayerTypeZKReq
}

func (z *ZKReq) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (z *ZKReq) Payload() []byte {
	return nil
}

func (z *ZKReq) LayerContents() []byte {
	return z.BaseLayer.LayerContents()
}

func (z *ZKReq) LayerPayload() []byte {
	return nil
}

type ZKResp struct {
	layers.BaseLayer

	Xid  int32
	Zxid int64
	Err  int32
}

func (z *ZKResp) LayerType() gopacket.LayerType {
	return LayerTypeZKResp
}

func decodeZKResp(data []byte, p gopacket.PacketBuilder) error {
	z := &ZKResp{}
	err := z.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(z)
	p.SetApplicationLayer(z)
	return nil
}

func (z *ZKResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		return ErrShortBuffer
	}
	// z.BaseLayer = layers.BaseLayer{Contents: data[:]}
	z.Xid = BytesToInt32(data[4:8])
	z.Zxid = BytesToInt64(data[8:16])
	z.Err = BytesToInt32(data[16:20])
	return nil
}

func (z *ZKResp) CanDecode() gopacket.LayerClass {
	return LayerTypeZKResp
}

func (z *ZKResp) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (z *ZKResp) Payload() []byte {
	return nil
}

func (z *ZKResp) LayerContents() []byte {
	return z.BaseLayer.LayerContents()
}

func (z *ZKResp) LayerPayload() []byte {
	return nil
}
