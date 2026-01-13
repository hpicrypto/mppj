package mppj

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

type PartyID string

type SessionID []byte

// NewSessionID generates a new session ID based on session participants and randomness.
func NewSessionID(sources []PartyID, helper, receiver string) SessionID {

	sidprime := uuid.New().String()

	info := fmt.Sprintf("%d", len(sources)) + "|" + helper + "|" + receiver
	for _, ds := range sources {
		info += "|" + string(ds)
	}

	sid, err := hkdf.Key(sha256.New, []byte(sidprime), nil, info, sha256.New().Size())
	if err != nil {
		panic(err)
	}

	return sid
}

type Session struct {
	ID         SessionID
	Sources    []PartyID
	Helper     PartyID
	Receiver   PartyID
	ReceiverPK PublicKey
}

func NewSession(sources []PartyID, helper, receiver PartyID, receiverPK PublicKey) (*Session, error) {
	if len(sources) < 2 {
		return nil, fmt.Errorf("at least two sources required")
	}
	if strings.EqualFold(string(helper), string(receiver)) {
		return nil, fmt.Errorf("helper and receiver must be different")
	}
	return &Session{
		ID:         NewSessionID(sources, string(helper), string(receiver)),
		Sources:    sources,
		Helper:     helper,
		Receiver:   receiver,
		ReceiverPK: receiverPK,
	}, nil
}

type contextKey string

const sourceIDContextKey = contextKey("source-id")

func SourceIDToOutgoingContext(ctx context.Context, id PartyID) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), string(sourceIDContextKey), string(id))
}

func SourceIDFromIncomingContext(ctx context.Context) (PartyID, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	id := md.Get(string(sourceIDContextKey))
	if len(id) == 0 {
		return "", false
	}
	return PartyID(id[0]), true
}

type SourceList []PartyID

func (s *SourceList) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *SourceList) Set(value string) error {
	ids := strings.Split(value, ",")
	for _, id := range ids {
		*s = append(*s, PartyID(id))
	}
	return nil
}
