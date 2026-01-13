package api

import (
	"fmt"
	"testing"

	"github.com/hpicrypto/mppj"

	"google.golang.org/protobuf/proto"
)

func TestSerializeMessages(t *testing.T) {

	sourceIDs := []mppj.PartyID{"ds1", "ds2", "ds3"}
	rsk, rpk := mppj.KeyGen()
	sess, err := mppj.NewSession(sourceIDs, "helper", "receiver", rpk)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Setup

	helper := mppj.NewHelper(sess)
	receiver := mppj.NewReceiver(sess, rsk)
	source := mppj.NewDataSource(sess)

	// Data sources do this:

	cuid, cval, err := source.ProcessRow("user1", "value1")
	if err != nil {
		t.Fatalf("ProcessRow failed: %v", err)
	}

	bcuid, _ := cuid.Serialize()
	fmt.Println("cuid size", len(bcuid))

	encRow := mppj.EncRow{Cuid: cuid, Cval: cval}
	encRowMsg, err := GetEncRowMsg(encRow)
	if err != nil {
		t.Fatalf("GetEncRowMsg failed: %v", err)
	}

	fmt.Println("Size of EncRow message:", proto.Size(encRowMsg))

	encRow, err = GetEncRowFromMsg(encRowMsg)
	if err != nil {
		t.Fatalf("GetEncRowFromMsg failed: %v", err)
	}

	encRowWithHint, err := helper.ConvertRow(receiver.GetPK(), &encRow, 1)
	if err != nil {
		t.Fatalf("ConvertRow failed: %v", err)
	}

	fmt.Println("Size of CVal", len(encRowWithHint.CVal))

	encRowWithHintMsg, err := GetEncRowWithHintMsg(*encRowWithHint)
	if err != nil {
		t.Fatalf("GetEncRowWithHintMsg failed: %v", err)
	}

	fmt.Println("Size of EncRowWithHint message:", proto.Size(encRowWithHintMsg))

	_, err = GetEncRowWithHintFromMsg(encRowWithHintMsg)
	if err != nil {
		t.Fatalf("GetEncRowWithHintFromMsg failed: %v", err)
	}
}
