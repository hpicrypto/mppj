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

// newPoint creates a new Point with coordinates (x, y) modulo the curve's prime P.
func newPoint() *point {
	return &point{p: group.NewElement()}
}

// Equals checks if two points a, b are equal by comparing their coordinates and ensuring they are on the curve.
func (a *point) Equals(b *point) bool {

	return a.p.IsEqual(b.p)

}

// gen returns the generator of the elliptic curve.
func gen() *point {
	return &point{p: group.Generator()}
}

// identity returns the the identitiy element of the elliptic curve.
func identity() *point {
	return &point{p: group.Identity()}
}

// mul performs the group operation on two points a, b on the elliptic curve.
func mul(a, b *point) *point {
	return &point{p: a.p.Copy().Add(a.p, b.p)}
}

// mulBatched performs the group operation on a slice of points.
func mulBatched(pointArr []*point) *point {
	if len(pointArr) == 0 {
		return newPoint()
	}
	result := pointArr[0]
	for _, point := range pointArr[1:] {
		result = mul(result, point)
	}
	return result
}

// baseExp exponentiates the generator by a scalar.
func baseExp(s *scalar) *point {
	return &point{p: group.NewElement().MulGen(s.s)}
}

// Inverts a point a on the elliptic curve.
func (a *point) invert() *point {
	return &point{p: a.p.Copy().Neg(a.p)}
}

// scalarExp exponentiates a point a by a scalar b on the elliptic curve.
func (a *point) scalarExp(b *scalar) *point {
	return &point{p: a.p.Copy().Mul(a.p, b.s)}
}

// produces a unifromly random point on the curve
func randomPoint() *point {
	s := group.RandomScalar(rand.Reader)
	return &point{p: group.NewElement().MulGen(s)} // faster than  group.RandomElement(rand.Reader)
}

// newScalar creates a new scalar from value.
func newScalar(value *big.Int) *scalar {
	return &scalar{s: group.NewScalar().SetBigInt(value)}
}

// Adds 2 scalars a, b.
func (a *scalar) add(b *scalar) *scalar {
	return &scalar{s: a.s.Copy().Add(a.s, b.s)}
}

func (a *scalar) Equals(b *scalar) bool {
	return a.s.IsEqual(b.s)
}

func (a *scalar) neg() *scalar {
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
