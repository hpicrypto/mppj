package mppj

import (
	"fmt"
	"strconv"
	"testing"
)

type benchParam struct {
	numParties int
	numRows    int
	joinSize   int
}

func BenchmarkSourceProcessRow(b *testing.B) {
	sourceIDs := []PartyID{"source1", "source2"}
	_, rpk := KeyGen()
	sess, err := NewSession(sourceIDs, "helper", "receiver", rpk)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}
	source := NewDataSource(sess)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := source.ProcessRow("user1", "value1")
		if err != nil {
			b.Fatalf("ProcessRow failed: %v", err)
		}
	}
}

func BenchmarkHelperConvertRow(b *testing.B) {
	sourceIDs := []PartyID{"source1", "source2"}
	_, rpk := KeyGen()
	sess, err := NewSession(sourceIDs, "helper", "receiver", rpk)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}
	source := NewDataSource(sess)
	helper := NewHelper(sess)

	cuid, cval, err := source.ProcessRow("user1", "value1")
	if err != nil {
		b.Fatalf("ProcessRow failed: %v", err)
	}
	encRow := EncRow{Cuid: cuid, Cval: cval}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := helper.ConvertRow(rpk, &encRow, sourceIDs[0])
		if err != nil {
			b.Fatalf("ConvertRow failed: %v", err)
		}
	}
}

func BenchmarkOps(b *testing.B) {
	sourceIDs := []PartyID{"source1", "source2"}
	_, rpk := KeyGen()
	sess, err := NewSession(sourceIDs, "helper", "receiver", rpk)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}

	ds := NewDataSource(sess)
	//helper := NewHelper(sess)
	tables := []TablePlain{make(TablePlain), make(TablePlain)}
	for i := range 10000 {
		tables[0][fmt.Sprintf("uid-%d", i)] = fmt.Sprintf("val-%d-1", i)
		tables[1][fmt.Sprintf("uid-%d", i)] = fmt.Sprintf("val-%d-0", i)
	}
	table := tables[0]
	b.ResetTimer()

	b.Run("PrepareStream", func(b *testing.B) {
		for b.Loop() {
			ds.PrepareStream(table)
		}
	})

}

var benchParams = []benchParam{
	{numParties: 2, numRows: 1000, joinSize: 500},
	{numParties: 3, numRows: 1000, joinSize: 500},
	{numParties: 2, numRows: 10000, joinSize: 5000},
	{numParties: 3, numRows: 10000, joinSize: 5000},
}

func BenchmarkFullJoin(b *testing.B) {

	for _, param := range benchParams {
		b.Run(fmt.Sprintf("%dP-%dRows-%dJoin", param.numParties, param.numRows, param.joinSize), func(b *testing.B) {

			dsNames := make([]PartyID, param.numParties)
			for i := 0; i < param.numParties; i++ {
				dsNames[i] = PartyID("ds" + strconv.Itoa(i+1))
			}
			rsk, rpk := KeyGen()
			sess, err := NewSession(dsNames, "helper", "receiver", rpk)
			if err != nil {
				b.Fatalf("Failed to create session: %v", err)
			}

			receiver := NewReceiver(sess, rsk)
			ds := NewDataSource(sess) // technically, only one data source instance is needed
			helper := NewHelper(sess)

			tables := GenTestTables(dsNames, param.numRows, param.joinSize)

			b.ResetTimer()

			encTables := make(map[PartyID]EncTable, 0)

			for b.Loop() {

				// Data sources do this:

				for sourceID, table := range tables {
					encTable, err := ds.Prepare(table)
					encTables[sourceID] = encTable
					if err != nil {
						b.Errorf("Error in Prepare: %v", err)
					}
				}

				// Send tables to helper
				// Helper does this:

				joinedTables, err := helper.Convert(encTables)
				if err != nil {
					b.Errorf("Error in Convert")
				}

				// Send tables to receiver
				// Receiver does this:

				receiver.JoinTables(joinedTables)
			}
		})

	}

}
