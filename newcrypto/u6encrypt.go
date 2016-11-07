package newcrypto

import "encoding/binary"

type cRand struct {
	state uint32
}

func (rand *cRand) rand() byte {
	rand.state = (0x41C64E6D * rand.state) + 0x3039
	return byte(rand.state >> 16)
}

func makeIv(rand *cRand) []byte {
	iv := make([]byte, 256)
	for i := 0; i < 256; i++ {
		iv[i] = rand.rand()
	}
	return iv
}

func makeIntegrityByte(rand *cRand) byte {
	lastbyte := rand.rand()
	v74 := (lastbyte ^ 0x0C) & lastbyte
	v75 := ((^v74 & 0x67) | (v74 & 0x98)) ^ 0x6F | (v74 & 8)
	return v75
}

func Encrypt(input []byte, msSinceStart uint32) []byte {
	rand := &cRand{msSinceStart}
	ivBlock := makeIv(rand)
	arr3 := make([]byte, 256)

	inputlen := len(input)
	blockcount := (inputlen + 256) / 256
	roundedsize := blockcount * 256
	totalsize := roundedsize + 4

	output := make([]byte, totalsize+1)

	binary.BigEndian.PutUint32(output, msSinceStart)
	copy(output[4:], input)

	// ANSI X.923 padding
	output[totalsize-1] = byte(roundedsize - inputlen)

	for offset := 4; offset < totalsize; offset += 256 {
		for i := 0; i < 256; i++ {
			output[offset+i] ^= ivBlock[i]
		}

		sub_9E9D8(AsDwordSlice(output[offset:offset+256]), AsDwordSlice(arr3))

		copy(ivBlock, arr3)
		copy(output[offset:], arr3)
	}

	output[totalsize] = makeIntegrityByte(rand)

	return output
}
