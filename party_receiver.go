package mppj

import (
	"fmt"
	"log"
	"runtime"
	"sync"
)

// Receiver represents the receiver party in the MPPJ protocol, for a given session. Its main method is JoinTables, which
// joins the converted encrypted tables from the helper.
type Receiver struct {
	sid       []byte
	sourceIDs []PartyID
	recvSK    SecretKey
	recvPK    PublicKey
}

// NewReceiver creates a new receiver for the given session.
func NewReceiver(sess *Session, sk SecretKey) *Receiver {
	r := &Receiver{
		sid:       sess.ID,
		sourceIDs: make([]PartyID, len(sess.Sources)),
		recvSK:    sk,
		recvPK:    sess.ReceiverPK,
	}
	copy(r.sourceIDs, sess.Sources)
	return r
}

// JoinTables extracts the intersection from the joined tables received from the helper.
func (r *Receiver) JoinTables(joinedTables EncTableWithHint) (JoinTable, error) {

	encrows := make(chan EncRowWithHint, len(joinedTables))

	go func() {
		defer close(encrows)
		for _, ct := range joinedTables {
			encrows <- ct
		}
	}()

	return r.JoinTablesStream(encrows)

}

// JoinTablesStream is the streaming version of [JoinTables]. It reads encrypted rows from the in channel,
// processes them, and returns the joined table when all the rows have been processed. It is optionally possible to specify
// the number of goroutines workers to use.
func (r *Receiver) JoinTablesStream(in chan EncRowWithHint, goroutines ...int) (JoinTable, error) {

	n := runtime.NumCPU()
	if len(goroutines) > 0 && goroutines[0] > 0 {
		n = goroutines[0]
	}

	groups := make(map[string][]EncRowWithHint)

	wg := sync.WaitGroup{}
	mu := sync.Mutex{}
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ciphertexts := range in {
				msgPRF, err := oprfUnblind(r.recvSK.bsk, &ciphertexts.Cnyme).GetMessageBytes()
				if err != nil {
					log.Fatalf("Decryption error: %v", err)
				}

				mu.Lock()
				groups[string(msgPRF)] = append(groups[string(msgPRF)], ciphertexts)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	return r.intersectHint(groups)
}

// GetPK returns the receiver's public key.
func (r *Receiver) GetPK() PublicKey {
	return r.recvPK
}

// GetSK returns the receiver's secret key.
func (r *Receiver) GetSK() SecretKey {
	return r.recvSK
}

type encValueWithHint struct {
	val        SymmetricCiphertext
	blindedkey message
	hint       message
}

func (r *Receiver) decryptGroup(group []EncRowWithHint) (map[PartyID]string, error) {
	decGroup := make([]encValueWithHint, len(group))

	for i, ge := range group {
		decGroup[i] = encValueWithHint{
			val:        ge.CVal,
			blindedkey: *oprfUnblind(r.recvSK.bsk, &ge.CValKey),
			hint:       *oprfUnblind(r.recvSK.bsk, &ge.CHint),
		}
	}

	mask := identity()
	for _, dge := range decGroup {
		mask = mul(mask, &dge.hint.m)
	}
	invMask := mask.invert()

	out := make(map[PartyID]string, len(group))
	for _, dge := range decGroup {
		keyp := mul(&dge.blindedkey.m, invMask)
		key, err := keyFromPoint(keyp, r.sid)
		if err != nil {
			panic(err)
		}

		encAttridValBytes, err := symmetricDecrypt(key, dge.val)
		if err != nil {
			panic(err)
		}

		if len(encAttridValBytes) == 0 {
			panic(fmt.Errorf("incorrect encrypted attribute value"))
		}

		sourceIndex, encValBytes := int(encAttridValBytes[0]), encAttridValBytes[1:]
		if sourceIndex < 0 || sourceIndex >= len(r.sourceIDs) {
			panic(fmt.Errorf("invalid source index: %d", sourceIndex))
		}
		sourceID := r.sourceIDs[sourceIndex]

		encVal, err := deserializeCiphertexts(encValBytes)
		if err != nil {
			panic(err)
		}

		plantext_data, err := decryptVectorPKE(r.recvSK.esk, encVal)
		if err != nil {
			panic(err)
		}

		out[sourceID] = string(plantext_data)
	}
	return out, nil
}

func (r *Receiver) intersectHint(groups map[string][]EncRowWithHint) (JoinTable, error) {

	decryptTasks := make(chan []EncRowWithHint)

	join := NewJoinTable(r.sourceIDs)
	mu := sync.Mutex{}

	wg := sync.WaitGroup{}
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for dectask := range decryptTasks {
				vals, err := r.decryptGroup(dectask)
				if err != nil {
					panic(err)
				}
				mu.Lock()
				if err := join.Insert(vals); err != nil {
					panic(err)
				}
				mu.Unlock()
			}
		}()
	}

	for _, group := range groups {
		if len(group) == len(r.sourceIDs) {
			decryptTasks <- group
		}
	}
	close(decryptTasks)

	wg.Wait()

	return join, nil
}
