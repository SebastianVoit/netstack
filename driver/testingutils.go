package driver

import "fmt"

// IxyDummy is a dummy implementation for testing purposes
type IxyDummy struct {
	Ixy IxyDevice
	// RX
	PktData  [][]byte
	RxMpool  *Mempool
	RxClosed []bool
	// TX
	Rec      [][]byte
	TxClosed []bool
}

// RxBatch is a dummy implementation for testing purposes
// fills all packet buffers with the data provided in PktData and then resets
func (d IxyDummy) RxBatch(queueID uint16, pb []*PktBuf) (uint32, error) {
	if d.RxClosed[queueID] {
		return 0, fmt.Errorf("rx queue closed")
	}
	if d.PktData == nil {
		return 0, nil
	}
	for i := 0; i < len(pb) && i < len(d.PktData); i++ {
		b := PktBufAlloc(d.RxMpool)
		if b == nil {
			return uint32(i), nil
		}
		copy(b.Pkt, d.PktData[i])
		b.Size = uint32(len(d.PktData[i]))
		pb[i] = b
	}
	d.PktData = nil
	return uint32(len(pb)), nil
}

// TxBatch is a dummy implementation for testing purposes
func (d IxyDummy) TxBatch(queueID uint16, pb []*PktBuf) (uint32, error) {
	if d.TxClosed[queueID] {
		return 0, fmt.Errorf("tx queue closed")
	}
	rec := make([][]byte, len(pb))
	for i := 0; i < len(pb); i++ {
		rec[i] = make([]byte, pb[i].Size)
		copy(rec[i], pb[i].Pkt)
		PktBufFree(pb[i])
	}
	d.Rec = rec
	return uint32(len(pb)), nil
}

// ReadStats is a dummy implementation for testing purposes
func (IxyDummy) ReadStats(_ *DeviceStats) {
}

func (IxyDummy) setPromisc(b bool) {
}

func (IxyDummy) getLinkSpeed() uint32 {
	return uint32(0)
}

// GetIxyDev is a dummy implementation for testing purposes
func (d IxyDummy) GetIxyDev() IxyDevice {
	return d.Ixy
}
