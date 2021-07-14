package phantomtcp

import (
	"encoding/binary"
)

func ComputeUDPChecksum(buffer []byte) uint16 {
	checksum := uint32(binary.BigEndian.Uint16(buffer[12:14]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[14:16]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[16:18]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[18:20]))
	checksum += uint32(17)
	checksum += uint32(binary.BigEndian.Uint16(buffer[24:26]))

	checksum += uint32(binary.BigEndian.Uint16(buffer[20:22]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[22:24]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[24:26]))

	offset := 28
	bufferLen := len(buffer)
	for {
		if offset > bufferLen-2 {
			if offset == bufferLen-1 {
				checksum += uint32(buffer[offset]) << 8
			}
			break
		}
		checksum += uint32(binary.BigEndian.Uint16(buffer[offset : offset+2]))
		offset += 2
	}

	checksum = (checksum & 0xffff) + (checksum >> 16)
	checksum = (checksum & 0xffff) + (checksum >> 16)

	return ^uint16(checksum)
}
