package mppj

type oprfKey scalar

// oprfKeyGen generates a new random key for the DH-OPRF.
func oprfKeyGen() *oprfKey {
	k := randomScalar()
	return (*oprfKey)(k)
}

// oprfBlind computes the encryption of m using the public key bpk.
func oprfBlind(bpk *publicKey, msg, sid []byte) *Ciphertext {
	hmsg := hashToMessage(msg, sid)
	return encryptPKE(bpk, hmsg)
}

// oprfUnblind computes the decryption of the ciphertext using the secret key bsk.
func oprfUnblind(bsk *secretKey, ciphertext *Ciphertext) *message {
	return decryptPKE(bsk, ciphertext)
}

// oprfEval computes the encryption of m^k. Computes ReRand internally.
func oprfEval(key *oprfKey, bpk *publicKey, ciphertext *Ciphertext) *Ciphertext {
	c0 := ciphertext.c0.ScalarExp((*scalar)(key))
	c1 := ciphertext.c1.ScalarExp((*scalar)(key))

	return reRand(bpk, &Ciphertext{c0: c0, c1: c1})
}
