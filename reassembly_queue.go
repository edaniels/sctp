// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

func sortChunksByTSN(a []*chunkPayloadData) {
	sort.Slice(a, func(i, j int) bool {
		return sna32LT(a[i].tsn, a[j].tsn)
	})
}

func sortChunksBySSN(a []*chunkSet) {
	sort.Slice(a, func(i, j int) bool {
		return sna16LT(a[i].ssn, a[j].ssn)
	})
}

func sortChunksByTSNThenSSN(a []*chunkSet) {
	sort.Slice(a, func(i, j int) bool {
		if sna32LT(a[i].tsn, a[j].tsn) {
			return true
		}
		return sna16LT(a[i].ssn, a[j].ssn)
	})
}

// chunkSet is a set of chunks that share the same SSN
type chunkSet struct {
	tsn    uint32
	epoch  uint32
	ssn    uint16 // used only with the ordered chunks
	ppi    PayloadProtocolIdentifier
	chunks []*chunkPayloadData
}

func newChunkSet(tsn uint32, epoch uint32, ssn uint16, ppi PayloadProtocolIdentifier) *chunkSet {
	return &chunkSet{
		tsn:    tsn,
		epoch:  epoch,
		ssn:    ssn,
		ppi:    ppi,
		chunks: []*chunkPayloadData{},
	}
}

func (set *chunkSet) push(chunk *chunkPayloadData) bool {
	// check if dup
	for _, c := range set.chunks {
		if c.tsn == chunk.tsn {
			return false
		}
	}

	// append and sort
	set.chunks = append(set.chunks, chunk)
	sortChunksByTSN(set.chunks)

	// Check if we now have a complete set
	complete := set.isComplete()
	return complete
}

func (set *chunkSet) isComplete() bool {
	// Condition for complete set
	//   0. Has at least one chunk.
	//   1. Begins with beginningFragment set to true
	//   2. Ends with endingFragment set to true
	//   3. TSN monotinically increase by 1 from beginning to end

	// 0.
	nChunks := len(set.chunks)
	if nChunks == 0 {
		println("REASON1")
		return false
	}

	// 1.
	if !set.chunks[0].beginningFragment {
		println("REASON2")
		return false
	}

	// 2.
	if !set.chunks[nChunks-1].endingFragment {
		println("REASON3")
		return false
	}

	// 3.
	var lastTSN uint32
	for i, c := range set.chunks {
		if i > 0 {
			// Fragments must have contiguous TSN
			// From RFC 4960 Section 3.3.1:
			//   When a user message is fragmented into multiple chunks, the TSNs are
			//   used by the receiver to reassemble the message.  This means that the
			//   TSNs for each fragment of a fragmented user message MUST be strictly
			//   sequential.
			if c.tsn != lastTSN+1 {
				println("REASON4", len(set.chunks), c.tsn, lastTSN)
				// mid or end fragment is missing
				return false
			}
		}

		lastTSN = c.tsn
	}

	return true
}

type reassemblyQueue struct {
	si               uint16
	nextSSN          uint16 // expected SSN for next ordered chunk
	tsnHighWatermark uint32
	ordered          []*chunkSet
	unordered        []*chunkSet
	unorderedChunks  []*chunkPayloadData
	nBytes           uint64
	mu               sync.RWMutex
	highestRead      uint16
	highestReadTSN   uint32
	pushSeen         map[uint16]string

	// TODO(erd): if this works, need a way to consume a constant memory
	epochs []uint32
}

var errTryAgain = errors.New("try again")

func newReassemblyQueue(si uint16) *reassemblyQueue {
	// From RFC 4960 Sec 6.5:
	//   The Stream Sequence Number in all the streams MUST start from 0 when
	//   the association is established.  Also, when the Stream Sequence
	//   Number reaches the value 65535 the next Stream Sequence Number MUST
	//   be set to 0.
	return &reassemblyQueue{
		si:        si,
		nextSSN:   0, // From RFC 4960 Sec 6.5:
		ordered:   make([]*chunkSet, 0),
		unordered: make([]*chunkSet, 0),
		pushSeen:  map[uint16]string{},
	}
}

func (r *reassemblyQueue) push(chunk *chunkPayloadData) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.pushSeen[chunk.streamSequenceNumber] = "push1"

	var cset *chunkSet

	if chunk.streamIdentifier != r.si {
		r.pushSeen[chunk.streamSequenceNumber] = "push2"
		return false
	}

	if chunk.unordered {
		// First, insert into unorderedChunks array
		r.unorderedChunks = append(r.unorderedChunks, chunk)
		atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))
		sortChunksByTSN(r.unorderedChunks)

		// Scan unorderedChunks that are contiguous (in TSN)
		cset = r.findCompleteUnorderedChunkSet()

		// If found, append the complete set to the unordered array
		if cset != nil {
			r.unordered = append(r.unordered, cset)
			r.pushSeen[chunk.streamSequenceNumber] = "push3"
			return true
		}

		r.pushSeen[chunk.streamSequenceNumber] = "push4"
		return false
	}

	// This is an ordered chunk

	if sna16LT(chunk.streamSequenceNumber, r.nextSSN) {
		r.pushSeen[chunk.streamSequenceNumber] = "push5"
		return false
	}

	epoch := uint32(len(r.epochs))
	for i, epochTSNCutoff := range r.epochs {
		if chunk.tsn <= epochTSNCutoff {
			epoch = uint32(i)
			break
		}
	}

	// Check if a chunkSet with the SSN already exists
	if !chunk.isUnfragmented() {
		for _, set := range r.ordered {
			// TODO(erd): add caution around SSN wrapping here...
			if set.ssn == chunk.streamSequenceNumber && chunk.isUnfragmented() {
				println("pushing to a set...", epoch, "we are epoch", len(r.epochs))
				cset = set
				break
			}
		}
	}

	// If not found, create a new chunkSet
	if cset == nil {
		cset = newChunkSet(chunk.tsn, epoch, chunk.streamSequenceNumber, chunk.payloadType)
		r.ordered = append(r.ordered, cset)
		if !chunk.unordered {
			sortChunksByTSNThenSSN(r.ordered)
		}
		// fmt.Println("appened", chunk.tsn, chunk.streamSequenceNumber, "at epoch", epoch, "while at major epoch", len(r.epochs), r.epochs, "and size is now", len(r.ordered), "with highest read at", r.highestRead, "overflow", r.highestRead > (1<<15)-1, "read_gap", int64(r.highestRead)-int64(r.ordered[0].ssn), int64(r.ordered[len(r.ordered)-1].ssn)-int64(r.highestRead))
	}

	atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))

	pret := cset.push(chunk)
	if pret {
		r.pushSeen[chunk.streamSequenceNumber] = "push6 " + fmt.Sprintf("%d", r.ordered[0].ssn)
	} else {
		r.pushSeen[chunk.streamSequenceNumber] = "push7"
	}
	return pret
}

func (r *reassemblyQueue) findCompleteUnorderedChunkSet() *chunkSet {
	r.mu.Lock()
	defer r.mu.Unlock()

	startIdx := -1
	nChunks := 0
	var lastTSN uint32
	var found bool

	for i, c := range r.unorderedChunks {
		// seek beigining
		if c.beginningFragment {
			startIdx = i
			nChunks = 1
			lastTSN = c.tsn

			if c.endingFragment {
				found = true
				break
			}
			continue
		}

		if startIdx < 0 {
			continue
		}

		// Check if contiguous in TSN
		if c.tsn != lastTSN+1 {
			startIdx = -1
			continue
		}

		lastTSN = c.tsn
		nChunks++

		if c.endingFragment {
			found = true
			break
		}
	}

	if !found {
		return nil
	}

	// Extract the range of chunks
	var chunks []*chunkPayloadData
	chunks = append(chunks, r.unorderedChunks[startIdx:startIdx+nChunks]...)

	r.unorderedChunks = append(
		r.unorderedChunks[:startIdx],
		r.unorderedChunks[startIdx+nChunks:]...)

	chunkSet := newChunkSet(0, 0, 0, chunks[0].payloadType)
	chunkSet.chunks = chunks

	return chunkSet
}

func (r *reassemblyQueue) isReadable() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check unordered first
	if len(r.unordered) > 0 {
		// The chunk sets in r.unordered should all be complete.
		return true
	}

	// Check ordered sets
	if len(r.ordered) > 0 {
		cset := r.ordered[0]
		if cset.isComplete() {
			// TODO(erd): something is wrong about this with respect to TSN
			// need to make an assumption about not having processed 2^16 -1 (2^15 - 1?)
			// SSNs to make some kind of reasonable ordering here...
			if sna16LTE(cset.ssn, r.nextSSN) {
				return true
			} else {
				// val, ok := couldPush[int(r.nextSSN)]
				// val2, ok2 := r.pushSeen[r.nextSSN]
				// fmt.Println("id love to return", cset.ssn, "but I have not seen", r.nextSSN, "yet",
				// 	"seen", ok, "pushed", val, r.highestRead, "seen here", ok2, val2,
				// 	"epoch is", fmt.Sprintf("%d:%d", r.highestReadTSN, r.epoch), "chunk epoch is", fmt.Sprintf("%d:%d", cset.tsn, cset.epoch), r.highestReadTSN > cset.tsn)
				// fmt.Println("id love to return", cset.ssn, cset.tsn, "from epoch", cset.epoch, "but my highest read is", r.highestRead, r.highestReadTSN, "at epoch", len(r.epochs), r.epochs, r.highestReadTSN > cset.tsn, cset.tsn < r.tsnHighWatermark, cset.tsn < r.highestReadTSN, len(r.ordered))
				// chunkDiag.PrintInfo(r.si, cset.ssn, cset.tsn)
				// chunkDiag.PrintInfoOnSSNCompare(r.si, r.highestRead, r.highestReadTSN)
				// chunkDiag.PrintInfoOnSSNCompare(r.si, r.highestRead-1, r.highestReadTSN)
				// chunkDiag.PrintInfoOnSSNCompare(r.si, r.highestRead+1, r.highestReadTSN)
				// for _, other := range r.ordered {
				// 	if other.tsn < r.highestReadTSN {
				// 		panic("OK1")
				// 	}
				// 	if other.epoch < uint32(len(r.epochs)) {
				// 		panic("OK2")
				// 	}
				// }
				// orderedSSN := make([]uint16, 0, len(r.ordered))
				// for _, c := range r.ordered {
				// 	orderedSSN = append(orderedSSN, c.ssn)
				// }
				// fmt.Println("ORDERED", orderedSSN)
			}
		} else {
			println("incomplete chunkset", cset.ssn)
		}
	}
	return false
}

var chunkDiag *chunkDiagnostics = newChunkDiagnostics()

type chunkDiagnostics struct {
	mu          sync.Mutex
	streamStats map[uint16]map[uint16][]*chunkStats
}

func newChunkDiagnostics() *chunkDiagnostics {
	return &chunkDiagnostics{
		streamStats: map[uint16]map[uint16][]*chunkStats{},
	}
}

type chunkStats struct {
	ssn      uint16
	tsn      uint32
	sent     int
	received int
}

func (cd *chunkDiagnostics) receiveChunk(chunk *chunkPayloadData) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if !chunk.isUnfragmented() {
		panic("CANNOT PROCESS")
	}
	if cd.streamStats[chunk.streamIdentifier] == nil {
		cd.streamStats[chunk.streamIdentifier] = map[uint16][]*chunkStats{}
	}
	if css, ok := cd.streamStats[chunk.streamIdentifier][chunk.streamSequenceNumber]; ok {
		for _, cs := range css {
			if cs.tsn == chunk.tsn {
				cs.received++
				return
			}
		}
	}
	panic(fmt.Errorf("never sent this so how could i get it lol sid=%d ssn=%d tsn=%d", chunk.streamIdentifier, chunk.streamSequenceNumber, chunk.tsn))
}

func (cd *chunkDiagnostics) sendChunk(chunk *chunkPayloadData) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if !chunk.isUnfragmented() {
		panic("CANNOT PROCESS")
	}

	if cd.streamStats[chunk.streamIdentifier] == nil {
		cd.streamStats[chunk.streamIdentifier] = map[uint16][]*chunkStats{}
	}
	if css, ok := cd.streamStats[chunk.streamIdentifier][chunk.streamSequenceNumber]; ok {
		for _, cs := range css {
			if cs.tsn == chunk.tsn {
				cs.sent++
				return
			}
		}
	}
	cd.streamStats[chunk.streamIdentifier][chunk.streamSequenceNumber] = append(cd.streamStats[chunk.streamIdentifier][chunk.streamSequenceNumber], &chunkStats{
		ssn:  chunk.streamSequenceNumber,
		tsn:  chunk.tsn,
		sent: 1,
	})
}

func (cd *chunkDiagnostics) PrintInfo(sid uint16, ssn uint16, tsn uint32) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if css, ok := cd.streamStats[sid][ssn]; ok {
		for _, cs := range css {
			if cs.tsn == tsn {
				fmt.Printf("Chunk sid=%d ssn=%d tsn=%d sent=%d recv=%d\n", sid, ssn, tsn, cs.sent, cs.received)
				return
			}
		}
	}
	fmt.Printf("No info found for sid=%d ssn=%d tsn=%d\n", sid, ssn, tsn)
	// for _, cs := range cd.streamStats[sid] {
	// 	fmt.Printf("Chunk sid=%d ssn=%d tsn=%d sent=%d recv=%d\n", sid, cs.ssn, cs.tsn, cs.sent, cs.received)
	// }
	panic("bad")
}

func (cd *chunkDiagnostics) PrintInfoOnSSNCompare(sid uint16, ssn uint16, compareTSN uint32) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if css, ok := cd.streamStats[sid][ssn]; ok {
		for _, cs := range css {
			fmt.Printf("Chunk sid=%d ssn=%d tsn=%d sent=%d recv=%d tsn_lte=%t\n", sid, ssn, cs.tsn, cs.sent, cs.received, sna32LTE(cs.tsn, compareTSN))
		}
		return
	}
	fmt.Printf("No info found for sid=%d ssn=%d\n", sid, ssn)
	// for _, cs := range cd.streamStats[sid] {
	// 	fmt.Printf("Chunk sid=%d ssn=%d tsn=%d sent=%d recv=%d\n", sid, cs.ssn, cs.tsn, cs.sent, cs.received)
	// }
	panic("bad")
}

func (r *reassemblyQueue) read(buf []byte) (int, PayloadProtocolIdentifier, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var cset *chunkSet
	// Check unordered first
	switch {
	case len(r.unordered) > 0:
		cset = r.unordered[0]
		r.unordered = r.unordered[1:]
	case len(r.ordered) > 0:
		// Now, check ordered
		cset = r.ordered[0]
		if !cset.isComplete() {
			return 0, 0, errTryAgain
		}
		if sna16GT(cset.ssn, r.nextSSN) {
			return 0, 0, errTryAgain
		}
		r.highestRead = cset.ssn
		r.highestReadTSN = cset.tsn
		r.ordered = r.ordered[1:]
		if cset.ssn == r.nextSSN {
			r.nextSSN++
			if r.nextSSN == 0 {
				// TODO(erd): any off by 1 here?
				r.epochs = append(r.epochs, cset.tsn)
				fmt.Println("epoch", len(r.epochs)-1, "cuts off at", cset.tsn)
			}
		} else {
			// println("NO INC", cset.ssn, r.nextSSN)
		}
	default:
		return 0, 0, errTryAgain
	}

	// Concat all fragments into the buffer
	nWritten := 0
	ppi := cset.ppi
	var err error
	for _, c := range cset.chunks {
		toCopy := len(c.userData)
		r.subtractNumBytes(toCopy)
		if err == nil {
			n := copy(buf[nWritten:], c.userData)
			nWritten += n
			if n < toCopy {
				err = io.ErrShortBuffer
			}
		}
	}

	return nWritten, ppi, err
}

func (r *reassemblyQueue) forwardTSNForOrdered(lastSSN uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Use lastSSN to locate a chunkSet then remove it if the set has
	// not been complete
	keep := []*chunkSet{}
	for _, set := range r.ordered {
		if sna16LTE(set.ssn, lastSSN) {
			if !set.isComplete() {
				// drop the set
				for _, c := range set.chunks {
					r.subtractNumBytes(len(c.userData))
				}
				continue
			}
		}
		keep = append(keep, set)
	}
	r.ordered = keep

	// Finally, forward nextSSN
	if sna16LTE(r.nextSSN, lastSSN) {
		r.nextSSN = lastSSN + 1
	}
}

func (r *reassemblyQueue) forwardTSNForUnordered(newCumulativeTSN uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove all fragments in the unordered sets that contains chunks
	// equal to or older than `newCumulativeTSN`.
	// We know all sets in the r.unordered are complete ones.
	// Just remove chunks that are equal to or older than newCumulativeTSN
	// from the unorderedChunks
	lastIdx := -1
	for i, c := range r.unorderedChunks {
		if sna32GT(c.tsn, newCumulativeTSN) {
			break
		}
		lastIdx = i
	}
	if lastIdx >= 0 {
		for _, c := range r.unorderedChunks[0 : lastIdx+1] {
			r.subtractNumBytes(len(c.userData))
		}
		r.unorderedChunks = r.unorderedChunks[lastIdx+1:]
	}
}

func (r *reassemblyQueue) subtractNumBytes(nBytes int) {
	cur := atomic.LoadUint64(&r.nBytes)
	if int(cur) >= nBytes {
		atomic.AddUint64(&r.nBytes, -uint64(nBytes))
	} else {
		atomic.StoreUint64(&r.nBytes, 0)
	}
}

func (r *reassemblyQueue) getNumBytes() int {
	return int(atomic.LoadUint64(&r.nBytes))
}
