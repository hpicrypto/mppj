package mppj

import (
	"errors"
	"math/big"
	"math/rand/v2"
	"runtime"
	"sync"
)

type Helper struct {
	sid           []byte
	sourceIndices map[PartyID]int
	rpk           PublicKey

	convK        *oprfKey
	padKeyShares []*scalar
	padKey       *scalar
}

// NewHelper creates a new Helper with the given key.
func NewHelper(sess *Session) *Helper {
	c := &Helper{sid: sess.ID, sourceIndices: make(map[PartyID]int), rpk: sess.ReceiverPK}
	for i, source := range sess.Sources {
		c.sourceIndices[source] = i
	}
	c.resetKey()
	c.genNonces(len(sess.Sources))
	return c
}

// resetKey generates a new  random key for the Helper.
func (h *Helper) resetKey() {
	k := oprfKeyGen()
	h.convK = k
}

func (h *Helper) getK() *oprfKey {
	return h.convK
}

// ResetKey generates a new  random key for the Helper.
func (h *Helper) genNonces(tableAmount int) {
	nonceSum := newScalar(big.NewInt(0))

	nonces := make([]*scalar, tableAmount)
	for i := range tableAmount {
		s := randomScalar()

		nonces[i] = s
		nonceSum = nonceSum.Add(s)
	}

	h.padKeyShares = nonces
	h.padKey = nonceSum

}

// blindAndHint produces an "ad" ciphertext, a blinded key, and a hint
func (h *Helper) blindAndHint(rpk PublicKey, joinid *Ciphertext, value []*Ciphertext, tindex int) ([]byte, *Ciphertext, *Ciphertext, error) {

	rp, key := RandomKeyFromPoint(h.sid)

	serialized, err := serializeCiphertexts(reRandVector(rpk.epk, value))
	if err != nil {
		return nil, nil, nil, err
	}

	ad, err := SymmetricEncrypt(key, append([]byte{byte(tindex)}, serialized...)) // append the table pos for in order reconstruction
	if err != nil {
		return nil, nil, nil, err
	}

	blindkey := oprfEval((*oprfKey)(h.padKey), rpk.bpk, joinid) // ReRand internally
	blindkey.c1 = Mul(blindkey.c1, rp)                          // blind the ephemeral point using joinid ^ s

	hint := oprfEval((*oprfKey)(h.padKeyShares[tindex]), rpk.bpk, joinid) // ReRand internally

	return ad, blindkey, hint, nil
}

// Convert performs DH-PRF on the hashed identifiers, blinds the data, then rerandomizes and shuffles all ciphertexts. GenNonces does not neet to be run before this function.
func (h *Helper) Convert(tables map[PartyID]EncTable) (EncTableWithHint, error) {

	encRowsTasks := make(chan ConvertRowTask)

	go func() {
		for sourceID, table := range tables {
			for _, row := range table {
				encRowsTasks <- ConvertRowTask{
					EncRowMsg:  EncRow{Cuid: row.Cuid, Cval: row.Cval},
					TableIndex: TableIndex(h.sourceIndices[sourceID]),
				}
			}
		}
		close(encRowsTasks)
	}()

	return h.ConvertStream(h.rpk, encRowsTasks)
}

type TableIndex int

type ConvertRowTask struct {
	EncRowMsg  EncRow
	TableIndex TableIndex
}

func (h *Helper) ConvertStream(rpk PublicKey, encRowsTasks chan ConvertRowTask) (EncTableWithHint, error) {

	if h.padKey == nil || h.padKeyShares == nil {
		return nil, errors.New("nonceerr, Nonces not generated. Please call GenNonces() before calling this function")
	}

	res := make(EncTableWithHint, 0)
	mu := new(sync.Mutex)

	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for encRow := range encRowsTasks {
				convRow, err := h.ConvertRow(rpk, &encRow.EncRowMsg, int(encRow.TableIndex))
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

func (h *Helper) ConvertRow(rpk PublicKey, r *EncRow, rid int) (*EncRowWithHint, error) {

	joinid := *oprfEval(h.convK, rpk.bpk, r.Cuid) // ReRand internally

	ad, blindedkey, hint, err := h.blindAndHint(rpk, &joinid, r.Cval, rid)
	if err != nil {
		panic(err)
	}
	return &EncRowWithHint{Cnyme: joinid, CVal: ad, CValKey: *blindedkey, CHint: *hint}, nil
}
