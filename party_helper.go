package mppj

import (
	"errors"
	"math/big"
	"math/rand/v2"
	"runtime"
	"sync"
)

// Helper represents a helper party in the MPPJ protocol, for a given session. Its main method is Convert, which
// converts encrypted tables from data sources into a format suitable for joining by the receiver.
type Helper struct {
	sid           []byte
	sourceIndices map[PartyID]int
	rpk           PublicKey

	convK        *oprfKey
	padKeyShares []*scalar
	padKey       *scalar
}

// NewHelper creates a new Helper for the given session.
func NewHelper(sess *Session) *Helper {
	c := &Helper{sid: sess.ID, sourceIndices: make(map[PartyID]int), rpk: sess.ReceiverPK}
	for i, source := range sess.Sources {
		c.sourceIndices[source] = i
	}
	c.convK = oprfKeyGen()
	c.padKeyShares, c.padKey = c.genNonces(len(sess.Sources))
	return c
}

// Convert converts the encrypted tables from data sources into a format suitable for joining by the receiver.
func (h *Helper) Convert(tables map[PartyID]EncTable) (EncTableWithHint, error) {

	encRowsTasks := make(chan ConvertRowTask)

	go func() {
		for sourceID, table := range tables {
			for _, row := range table {
				encRowsTasks <- ConvertRowTask{
					EncRowMsg: EncRow{Cuid: row.Cuid, Cval: row.Cval},
					SourceID:  sourceID,
				}
			}
		}
		close(encRowsTasks)
	}()

	return h.ConvertStream(h.rpk, encRowsTasks)
}

// ConvertRowTask represents a task to convert a single encrypted row from a data source.
type ConvertRowTask struct {
	EncRowMsg EncRow
	SourceID  PartyID
}

// ConvertStream is the streaming version of [Convert]. It reads encrypted rows from the encRowsTasks channel,
// processes them, and returns the converted table when all the rows have been processed. It is optionally possible to specify
// the number of goroutines workers to use.
func (h *Helper) ConvertStream(rpk PublicKey, encRowsTasks chan ConvertRowTask, goroutines ...int) (EncTableWithHint, error) {

	if h.padKey == nil || h.padKeyShares == nil {
		return nil, errors.New("nonceerr, Nonces not generated. Please call GenNonces() before calling this function")
	}

	n := runtime.NumCPU()
	if len(goroutines) > 0 && goroutines[0] > 0 {
		n = goroutines[0]
	}

	res := make(EncTableWithHint, 0)
	mu := new(sync.Mutex)

	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for encRow := range encRowsTasks {
				convRow, err := h.ConvertRow(rpk, &encRow.EncRowMsg, encRow.SourceID)
				if err != nil {
					panic(err)
				}
				mu.Lock()
				res = append(res, *convRow)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	rand.Shuffle(len(res), func(i, j int) { // TODO: use proper RNG
		res[i], res[j] = res[j], res[i]
	})

	return res, nil
}

// ConvertRow converts a single row `r` received from datasource sourceID.
func (h *Helper) ConvertRow(rpk PublicKey, r *EncRow, sourceID PartyID) (*EncRowWithHint, error) {

	joinid := *oprfEval(h.convK, rpk.bpk, r.Cuid) // ReRand internally

	ad, blindedkey, hint, err := h.blindAndHint(rpk, &joinid, r.Cval, h.sourceIndices[sourceID])
	if err != nil {
		panic(err)
	}
	return &EncRowWithHint{Cnyme: joinid, CVal: ad, CValKey: *blindedkey, CHint: *hint}, nil
}

func (h *Helper) genNonces(nSources int) ([]*scalar, *scalar) {

	nonces := make([]*scalar, nSources)
	nonceSum := newScalar(big.NewInt(0))
	for i := range nSources {
		nonces[i] = randomScalar()
		nonceSum = nonceSum.add(nonces[i])
	}

	return nonces, nonceSum
}

func (h *Helper) blindAndHint(rpk PublicKey, joinid *Ciphertext, value []*Ciphertext, tindex int) ([]byte, *Ciphertext, *Ciphertext, error) {

	rp, key := randomKeyFromPoint(h.sid)

	serialized, err := serializeCiphertexts(reRandVector(rpk.epk, value))
	if err != nil {
		return nil, nil, nil, err
	}

	ad, err := symmetricEncrypt(key, append([]byte{byte(tindex)}, serialized...)) // append the table pos for in order reconstruction
	if err != nil {
		return nil, nil, nil, err
	}

	blindkey := oprfEval((*oprfKey)(h.padKey), rpk.bpk, joinid) // ReRand internally
	blindkey.c1 = mul(blindkey.c1, rp)                          // blind the ephemeral point using joinid ^ s

	hint := oprfEval((*oprfKey)(h.padKeyShares[tindex]), rpk.bpk, joinid) // ReRand internally

	return ad, blindkey, hint, nil
}
