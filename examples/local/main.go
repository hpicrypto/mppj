package main

import (
	"fmt"

	"github.com/hpicrypto/mppj"
)

func MPPJ() {

	numRows := 100
	joinSize := 10

	fmt.Println("----- MPPJ -----")
	fmt.Println("")

	sourceIDs := []mppj.PartyID{"ds1", "ds2", "ds3"}
	rsk, rpk := mppj.KeyGen()
	sess, err := mppj.NewSession(sourceIDs, "helper", "receiver", rpk)
	if err != nil {
		panic(err)
	}

	// Setup phase

	receiver := mppj.NewReceiver(sess, rsk)
	ds := mppj.NewDataSource(sess) // technically, only one data source instance is needed
	converter := mppj.NewHelper(sess)

	// Data sources do this:
	tables := mppj.GenTestTables(sourceIDs, numRows, joinSize)

	// Encrypting the tables

	encTables := make(map[mppj.PartyID]mppj.EncTable, 0)

	for sourceID, table := range tables {
		encTable, _ := ds.Prepare(table)
		encTables[sourceID] = encTable
	}

	// Send tables to converter
	// Converter does this:

	joinedTables, _ := converter.Convert(encTables)

	// Send tables to receiver
	// Receive phase
	// Receiver does this:

	intersectionMPPJ, _ := receiver.JoinTables(joinedTables)

	fmt.Println("Tables after Join (Pseudonymized)")

	fmt.Println(intersectionMPPJ, "\n length ", intersectionMPPJ.Len())

	// Check results

	// Plaintext join
	joinedTablesPlain := mppj.IntersectSimple(tables, sourceIDs)

	fmt.Println("Intersection of tables (plaintext):")
	fmt.Println(joinedTablesPlain, "\n length ", joinedTablesPlain.Len())

	fmt.Println("Are tables' contents equal?", joinedTablesPlain.EqualContents(&intersectionMPPJ))
}

func main() {
	MPPJ()
}
