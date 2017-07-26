package main

import (
	// "fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	LayerTypeZKReq  = gopacket.RegisterLayerType(2003, gopacket.LayerTypeMetadata{Name: "ZKReq", Decoder: gopacket.DecodeFunc(decodeZKReq)})
	LayerTypeZKResp = gopacket.RegisterLayerType(2004, gopacket.LayerTypeMetadata{Name: "ZKResp", Decoder: gopacket.DecodeFunc(decodeZKResp)})
)

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
	case opNotify:
		z.Optype = "CONNECT"
	case opCreate:
		z.Optype = "CREATE"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
		dataLen := BytesToInt32(data[n : n+4])
		n = n + 4
		z.Data = data[n : n+dataLen]
	case opDelete:
		z.Optype = "DELETE"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case opExists:
		z.Optype = "EXISTS"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
		if int(n+1) <= len(data) {
			watch := BytesToBool(data[n : n+1])
			if watch {
				z.Optype = "EXISTS_W"
			}
		}
	case opGetData:
		z.Optype = "GETDATA"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
		if int(n+1) <= len(data) {
			watch := BytesToBool(data[n : n+1])
			if watch {
				z.Optype = "GETDATA_W"
			}
		}
	case opSetData:
		z.Optype = "SETDATA"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
		dataLen := BytesToInt32(data[n : n+4])
		n = n + 4
		z.Data = data[n : n+dataLen]
	case opGetAcl:
		z.Optype = "GETACL"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case opSetAcl:
		z.Optype = "SETACL"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case opGetChildren:
		z.Optype = "GETCHILDREN"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
		if int(n+1) <= len(data) {
			watch := BytesToBool(data[n : n+1])
			if watch {
				z.Optype = "GETCHILDREN_W"
			}
		}
	case opSync:
		z.Optype = "SYNC"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case opPing:
		z.Optype = "PING"
	case opGetChildren2:
		z.Optype = "GETCHILDREN2"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
		if int(n+1) <= len(data) {
			watch := BytesToBool(data[n : n+1])
			if watch {
				z.Optype = "GETCHILDREN2_W"
			}
		}
	case opCheck:
		z.Optype = "CHECK"
	case opMulti:
		z.Optype = "MULTI"
	case opCreate2:
		z.Optype = "CREATE2"
		pathLen := BytesToInt32(data[12:16])
		n := 16 + pathLen
		z.Path = string(data[16:n])
	case opReconfig:
		z.Optype = "RECONFIG"
	case opError:
		z.Optype = "ERROR"
	case opCreateSession:
		z.Optype = "CREATESESSION"
	case opClose:
		z.Optype = "CLOSE"
	case opSetAuth:
		z.Optype = "SETAUTH"
	case opSetWatches:
		z.Optype = "SETWATCHES"
	default:
		// fmt.Printf("Unknown Opcode: %d\n", z.Opcode)
		z.Optype = "UNKNOWN"
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
