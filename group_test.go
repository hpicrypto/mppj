package mppj

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

func TestKyber(t *testing.T) {

	//fmt.Println(p.EmbedLen())
}

func BenchmarkEmbed(b *testing.B) {

	msg := []byte("DEADBEEFCAFEFACEBAD")
	suite := suites.MustFind("P256")

	rnd := random.New()
	b.Run("Kyber", func(b *testing.B) {
		p := suite.Point()
		p.Embed(msg, rnd)
	})

	b.Run("Ours", func(b *testing.B) {
		msg, err := newMessageFromBytes(msg)
		if err != nil {
			panic(err)
		}
		_ = msg

	})
}

func TestNewMessage(t *testing.T) {
	tests := []struct {
		name     string
		msgBytes []byte
		wantErr  bool
	}{
		{
			name:     "Valid message",
			msgBytes: []byte{1},
			wantErr:  false,
		},
		{
			name:     "Zero message",
			msgBytes: []byte{0},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := newMessageFromBytes(tt.msgBytes)
			if err != nil && !tt.wantErr {
				t.Errorf("NewMessage() error = %v, want nil", err)
			}
			if msg == nil && !tt.wantErr {
				t.Errorf("NewMessage() returned nil, expected valid message")
			}
			if msg == nil && !tt.wantErr {
				t.Errorf("NewMessage() returned nil, expected valid message")
			}
			if msg != nil && tt.wantErr {
				t.Errorf("NewMessage() returned valid message, expected error")
			}
		})
	}
}

func TestGetMessage(t *testing.T) {
	msgBytes := make([]byte, 16)
	_, err := rand.Read(msgBytes)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	msg, err := newMessageFromBytes(msgBytes)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}
	got, err := msg.GetMessageStringHex()
	if err != nil {
		t.Fatalf("Failed to get message string: %v", err)
	}
	if hex.EncodeToString(msgBytes) != got {
		t.Errorf("GetMessage() = %v, want %v", got, hex.EncodeToString(msgBytes))
	}
}

func TestRandomMsg(t *testing.T) {
	msg, err := randomMsg()
	if err != nil {
		t.Errorf("RandomMsg() error = %v", err)
	}
	if msg == nil {
		t.Errorf("RandomMsg() returned nil, expected valid message")
	}
}

func TestScalarMul(t *testing.T) {
	tests := []struct {
		name string
		a    *point
		b    *scalar
		want *point
	}{
		{
			name: "Scalar multiplication with base point",
			a:    gen(),
			b:    newScalar(big.NewInt(2)),
			want: gen().scalarExp(newScalar(big.NewInt(2))),
		},
		{
			name: "Scalar multiplication with one",
			a:    gen(),
			b:    newScalar(big.NewInt(1)),
			want: gen(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.scalarExp(tt.b)
			if !got.Equals(tt.want) {
				t.Errorf("ScalarMul() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRandomPoint(t *testing.T) {
	point := randomPoint()

	if point == nil {
		t.Fatalf("GetRandomPoint() returned nil point")
	}

}

func TestAdd(t *testing.T) {
	tests := []struct {
		name string
		a, b *point
		want *point
	}{
		{
			name: "Add base point to itself",
			a:    gen(),
			b:    gen(),
			want: mul(gen(), gen()),
		},
		{
			name: "Add base point to zero point",
			a:    gen(),
			b:    identity(),
			want: gen(),
		},
		{
			name: "Add zero point to base point",
			a:    identity(),
			b:    gen(),
			want: gen(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mul(tt.a, tt.b); !got.Equals(tt.want) {
				t.Errorf("Add() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvert(t *testing.T) {
	tests := []struct {
		name  string
		point *point
		want  *point
	}{
		{
			name:  "Invert base point",
			point: gen(),
			want:  baseExp(newScalar(big.NewInt(1)).neg()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.point.invert(); !got.Equals(tt.want) {
				t.Errorf("Invert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvert2(t *testing.T) {
	point := randomPoint()

	inverted := point.invert()
	if inverted == nil {
		t.Fatalf("Invert() returned nil point")
	}

	if !mul(mul(point, inverted), gen()).Equals(gen()) {
		t.Errorf("Invert() failed to invert point")
	}
}

func TestInvert3(t *testing.T) {
	point := randomPoint()

	inverted := point.invert()
	if inverted == nil {
		t.Fatalf("Invert() returned nil point")
	}

	if !mul(mul(point, gen()), inverted).Equals(gen()) {
		t.Errorf("Invert() failed to invert point")
	}
}

func TestEncrypt(t *testing.T) {
	msgBytes := make([]byte, 16)
	_, err := rand.Read(msgBytes)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	msg, err := newMessageFromBytes(msgBytes)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	_, pk := keyGenPKE()

	ciphertext := encryptPKE(pk, msg)
	if ciphertext == nil {
		t.Fatalf("Encrypt() returned nil ciphertext")
	}

	if ciphertext.c0 == nil || ciphertext.c1 == nil {
		t.Fatalf("Encrypt() returned ciphertext with nil components")
	}
}

func TestEqual(t *testing.T) {
	a := gen()
	b := gen()
	if !a.Equals(b) {
		t.Errorf("Equals() = false, want true")
	}
}

func TestSerializeDeserializePoint(t *testing.T) {
	// Generate a random point
	point := randomPoint()

	// Serialize the point
	serializedPoint, err := point.MarshalBinary()
	if err != nil {
		t.Fatalf("SerializePoint() error = %v", err)
	}

	// Deserialize the point
	deserializedPoint := newPoint()

	err = deserializedPoint.UnmarshalBinary(serializedPoint)
	if err != nil {
		t.Fatalf("DeserializePoint() error = %v", err)
	}

	// Check if the deserialized point matches the original point
	if !point.Equals(deserializedPoint) {
		t.Errorf("DeserializePoint() = %v, want %v", deserializedPoint, point)
	}
}

func TestSerializeDeserializeCiphertext(t *testing.T) {

	point1 := randomPoint()
	point2 := randomPoint()

	ciphertext := &Ciphertext{c0: point1, c1: point2}

	// Serialize the ciphertext
	serializedCiphertext, err := ciphertext.Serialize()
	if err != nil {
		t.Fatalf("SerializeCiphertext() error = %v", err)
	}

	// Deserialize the ciphertext
	deserializedCiphertext, err := DeserializeCiphertext(serializedCiphertext)
	if err != nil {
		t.Fatalf("DeserializeCiphertext() error = %v", err)
	}

	// Check if the deserialized ciphertext matches the original ciphertext
	if !deserializedCiphertext.Equals(ciphertext) {
		t.Errorf("DeserializeCiphertext() = %v, want %v", deserializedCiphertext, ciphertext)
	}
}

func TestSerializeDeserializeCiphertext2(t *testing.T) {

	c0 := randomPoint()

	c1 := randomPoint()

	ciphertext := &Ciphertext{c0: c0, c1: c1}

	// Serialize the ciphertext
	serializedCiphertext, err := ciphertext.Serialize()
	if err != nil {
		t.Fatalf("SerializeCiphertext() error = %v", err)
	}

	// Deserialize the ciphertext
	deserializedCiphertext, err := DeserializeCiphertext(serializedCiphertext)
	if err != nil {
		t.Fatalf("DeserializeCiphertext() error = %v", err)
	}

	// Check if the deserialized ciphertext matches the original ciphertext
	if !deserializedCiphertext.Equals(ciphertext) {
		t.Errorf("DeserializeCiphertext() = %v, want %v", deserializedCiphertext, ciphertext)
	}
}

func TestScalarAddition(t *testing.T) {
	s1 := randomScalar()

	s2 := randomScalar()

	s3 := s1.add(s2)

	if !s3.Equals(s1.add(s2)) {
		t.Errorf("Addition failed: %s + %s != %s", s1, s2, s3)
	}
}

func TestScalarAdditionExp(t *testing.T) {

	for i := 0; i < 100; i++ {
		s1 := randomScalar()
		s2 := randomScalar()

		s3 := s1.add(s2)

		if !baseExp(s3).Equals(mul(baseExp(s2), baseExp(s1))) {
			t.Errorf("Addition %d failed: %s + %s != %s", i, baseExp(s3), baseExp(s2), baseExp(s1))
		}
	}
}

func TestSecretExponentiationGen(t *testing.T) {

	num_shares := 10
	nonceSum := newScalar(big.NewInt(0))
	blind_shares := make([]*point, num_shares)

	nonces := make([]*scalar, num_shares)
	for i := range num_shares {
		s := randomScalar()

		nonces[i] = s.Copy()
		blind_shares[i] = baseExp(nonces[i].Copy())
		nonceSum = nonceSum.add(nonces[i].Copy())
	}

	blind := baseExp(nonceSum)
	decKeyTemp := mulBatched(blind_shares)

	if !blind.Equals(decKeyTemp) {
		t.Errorf("Secrets do not match: %s != %s", blind, decKeyTemp)
	}
}

func TestSecretExponentiation(t *testing.T) {

	num_shares := 10
	blind_base := randomPoint()
	nonceSum := newScalar(big.NewInt(0))
	blind_shares := make([]*point, num_shares)

	nonces := make([]*scalar, num_shares)
	for i := range num_shares {
		s := randomScalar()

		nonces[i] = s
		blind_shares[i] = blind_base.scalarExp(s)
		nonceSum = nonceSum.add(s)
	}

	blind := blind_base.scalarExp(nonceSum)
	decKeyTemp := mulBatched(blind_shares)

	if !blind.Equals(decKeyTemp) {
		t.Errorf("Secrets do not match: %s != %s", blind, decKeyTemp)
	}
}

func TestPlantextSecretSharing(t *testing.T) {

	rp := randomPoint()
	num_shares := 10
	blind_base := randomPoint()
	nonceSum := newScalar(big.NewInt(0))

	nonces := make([]*scalar, num_shares)
	for i := range num_shares {
		s := randomScalar()

		nonces[i] = s
		nonceSum = nonceSum.add(s)
	}

	blind := blind_base.scalarExp(nonceSum)
	blinded_point := mul(rp, blind)

	decKeyTemp := gen() // no identity in this lib for now :(
	for _, nonce := range nonces {
		decKeyTemp = mul(decKeyTemp, blind_base.scalarExp(nonce))
	}

	decKeyTemp = mul(decKeyTemp, gen().invert()).invert()
	recovered_rp := mul(blinded_point, decKeyTemp)

	if !rp.Equals(recovered_rp) {
		t.Errorf("Secrets do not match: %s != %s", rp, recovered_rp)
	}
}
