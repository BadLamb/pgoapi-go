package newcrypto

import (
	"encoding/binary"
	"math"
)

const (
	hashLocation1 = iota
	hashLocation2
	hashRequest
)

type HashRequest struct {
	HashType   int
	Lat        float64
	Lng        float64
	Alt        float64
	AuthTicket []byte
	Request    []byte

	Result chan uint64
}

func locationToBuffer(lat, lng, alt float64) []byte {
	buffer := make([]byte, 24)

	binary.BigEndian.PutUint64(buffer[0:], math.Float64bits(lat))
	binary.BigEndian.PutUint64(buffer[8:], math.Float64bits(lng))
	binary.BigEndian.PutUint64(buffer[16:], math.Float64bits(alt))

	return buffer
}

type PogoSignature struct {
	requestChannel chan *HashRequest
}

func NewPogoSignature() *PogoSignature {
	return &PogoSignature{
		make(chan *HashRequest),
	}
}

func (ps *PogoSignature) ProcessSignatureRequests() error {

	for {
		hr := <-ps.requestChannel

		switch hr.HashType {
		case hashLocation1:
			seed := Hash32(hr.AuthTicket)
			payload := locationToBuffer(hr.Lat, hr.Lng, hr.Alt)
			hash := Hash32Salt(payload, seed)
			hr.Result <- uint64(hash)
		case hashLocation2:
			payload := locationToBuffer(hr.Lat, hr.Lng, hr.Alt)
			hash := Hash32(payload)
			hr.Result <- uint64(hash)
		case hashRequest:
			seed := Hash64(hr.AuthTicket)
			hash := Hash64Salt64(hr.Request, seed)
			hr.Result <- hash
		}
	}
}

func (ps *PogoSignature) HashLocation1(authTicket []byte, lat, lng, alt float64) uint32 {
	resultChannel := make(chan uint64, 1)
	ps.requestChannel <- &HashRequest{
		HashType:   hashLocation1,
		AuthTicket: authTicket,
		Lat:        lat,
		Lng:        lng,
		Alt:        alt,
		Result:     resultChannel,
	}
	return uint32(<-resultChannel)
}

func (ps *PogoSignature) HashLocation2(lat, lng, alt float64) uint32 {
	resultChannel := make(chan uint64, 1)
	ps.requestChannel <- &HashRequest{
		HashType: hashLocation2,
		Lat:      lat,
		Lng:      lng,
		Alt:      alt,
		Result:   resultChannel,
	}
	return uint32(<-resultChannel)
}

func (ps *PogoSignature) HashRequest(authTicket, request []byte) uint64 {
	resultChannel := make(chan uint64, 1)
	ps.requestChannel <- &HashRequest{
		HashType:   hashRequest,
		AuthTicket: authTicket,
		Request:    request,
		Result:     resultChannel,
	}
	return <-resultChannel
}

func (ps *PogoSignature) Hash25() int64 {
	return -8408506833887075802
}
