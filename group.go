package mppj

import (
	"crypto/rand"
	"math/big"

	circl "github.com/cloudflare/circl/group"
)

var group = circl.P256

// scalar represents a scalar value modulo the curve's order
type scalar struct {
	s circl.Scalar
}

// point represents a point on the elliptic curve.
type point struct {
	p circl.Element
}

// SerializePoint serializes a Point into a byte slice.
func (p *point) MarshalBinary() ([]byte, error) {

	return p.p.MarshalBinaryCompress()
}

// DeserializePoint deserializes a byte slice into a Point.
func (p *point) UnmarshalBinary(data []byte) error {
	err := p.p.UnmarshalBinary(data)
	return err
}

// NewPoint creates a new Point with coordinates (x, y) modulo the curve's prime P.
func NewPoint() *point {
	return &point{p: group.NewElement()}
}

// Equals checks if two points a, b are equal by comparing their coordinates and ensuring they are on the curve.
func (a *point) Equals(b *point) bool {

	return a.p.IsEqual(b.p)

}

// Gen returns the generator of the elliptic curve.
func Gen() *point {
	return &point{p: group.Generator()}
}

// Identity returns the the identitiy element of the elliptic curve.
func Identity() *point {
	return &point{p: group.Identity()}
}

// Mul performs the group operation on two points a, b on the elliptic curve.
func Mul(a, b *point) *point {
	return &point{p: a.p.Copy().Add(a.p, b.p)}
}

// mulBatched performs the group operation on a slice of points.
func mulBatched(pointArr []*point) *point {
	if len(pointArr) == 0 {
		return NewPoint()
	}
	result := pointArr[0]
	for _, point := range pointArr[1:] {
		result = Mul(result, point)
	}
	return result
}

// BaseExp exponentiates the generator by a scalar.
func BaseExp(s *scalar) *point {
	return &point{p: group.NewElement().MulGen(s.s)}
}

// Inverts a point a on the elliptic curve.
func (a *point) Invert() *point {
	return &point{p: a.p.Copy().Neg(a.p)}
}

// ScalarExp exponentiates a point a by a scalar b on the elliptic curve.
func (a *point) ScalarExp(b *scalar) *point {
	return &point{p: a.p.Copy().Mul(a.p, b.s)}
}

// InvertScalar returns the multiplicative inverse of a scalar.
func (s *scalar) Invert() *scalar {
	return &scalar{s: s.s.Copy().Inv(s.s)}
}

// produces a unifromly random point on the curve
func randomPoint() *point {
	s := group.RandomScalar(rand.Reader)
	return &point{p: group.NewElement().MulGen(s)} // faster than  group.RandomElement(rand.Reader)
}

// NewScalar creates a new scalar from value.
func newScalarEmpty() *scalar {
	return &scalar{s: group.NewScalar()}
}

// newScalar creates a new scalar from value.
func newScalar(value *big.Int) *scalar {
	return &scalar{s: group.NewScalar().SetBigInt(value)}
}

// Adds 2 scalars a, b.
func (a *scalar) Add(b *scalar) *scalar {
	return &scalar{s: a.s.Copy().Add(a.s, b.s)}
}

// Multiplies 2 scalars a, b.
func (a *scalar) Mul(b *scalar) *scalar {
	return &scalar{s: a.s.Copy().Mul(a.s, b.s)}
}

func (a *scalar) Equals(b *scalar) bool {
	return a.s.IsEqual(b.s)
}

func (a *scalar) Neg() *scalar {
	return &scalar{s: a.s.Copy().Neg(a.s)}
}

func (a *scalar) Copy() *scalar {
	return &scalar{s: a.s.Copy()}
}

// randomScalar creates a new random scalar.
func randomScalar() *scalar {

	return &scalar{
		s: group.RandomScalar(rand.Reader),
	}
}

// hashToPoint hashes a byte slice to a scalar. See hash to field/group RFC
func hashToPoint(msg, sid []byte) *point {
	prefix := []byte("hash_to_element")
	dst := append(prefix, sid...)
	return &point{p: group.HashToElement(msg, dst)}
}
