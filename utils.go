package main

import (
	"encoding/binary"
)

/*----------------------------------------------
 *
 * 基本类型编码成字节数组
 *
 ----------------------------------------------*/

func Int32ToBytes(buf []byte, i int32) {
	binary.BigEndian.PutUint32(buf, uint32(i))
}

func Int64ToBytes(buf []byte, i int64) {
	binary.BigEndian.PutUint64(buf, uint64(i))
}

func BoolToBytes(buf []byte, b bool) {
	if b {
		buf[0] = 1
	} else {
		buf[0] = 0
	}
}

/*----------------------------------------------
 *
 * 节点数组解码成基本类型
 *
 ----------------------------------------------*/

func BytesToInt32(buf []byte) int32 {
	if len(buf) < 4 {
		return int32(0)
	}
	return int32(binary.BigEndian.Uint32(buf))
}

func BytesToInt64(buf []byte) int64 {
	if len(buf) < 8 {
		return int64(0)
	}
	return int64(binary.BigEndian.Uint64(buf))
}

func BytesToBool(buf []byte) bool {
	if len(buf) < 0 {
		return false
	}
	if buf[0] == 1 {
		return true
	}
	return false
}
