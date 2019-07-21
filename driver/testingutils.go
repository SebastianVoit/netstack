package driver

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
func (d IxyDummy) RxBatch(_ uint16, pb []*PktBuf) uint32 {
	if d.PktData == nil {
		return 0
	}
	for i := 0; i < len(pb) && i < len(d.PktData); i++ {
		b := PktBufAlloc(d.RxMpool)
		if b == nil {
			return uint32(i)
		}
		copy(b.Pkt, d.PktData[i])
		b.Size = uint32(len(d.PktData[i]))
		pb[i] = b
	}
	d.PktData = nil
	return uint32(len(pb))
}

// TxBatch is a dummy implementation for testing purposes
func (d IxyDummy) TxBatch(_ uint16, pb []*PktBuf) uint32 {
	rec := make([][]byte, len(pb))
	for i := 0; i < len(pb); i++ {
		rec[i] = make([]byte, pb[i].Size)
		copy(rec[i], pb[i].Pkt)
		PktBufFree(pb[i])
	}
	d.Rec = rec
	return uint32(len(pb))
}

// CloseRxQueue closes rx queue of the dummy
func (d *IxyDummy) CloseRxQueue(queueID uint16) {
	d.RxClosed[queueID] = true
}

// ClosedRx returns whether the rx queue is closed
func (d *IxyDummy) ClosedRx(queueID uint16) bool {
	return d.RxClosed[queueID]
}

// CloseTxQueue closes tx queue of the dummy
func (d *IxyDummy) CloseTxQueue(queueID uint16) {
	d.TxClosed[queueID] = true
}

// ClosedTx returns whether the tx queue is closed
func (d *IxyDummy) ClosedTx(queueID uint16) bool {
	return d.TxClosed[queueID]
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
