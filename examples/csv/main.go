package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"

	"github.com/hpicrypto/mppj"
)

func extractTables(sourceIDs []mppj.PartyID) map[mppj.PartyID]mppj.TablePlain {

	tables := make(map[mppj.PartyID]mppj.TablePlain)

	for i, tableName := range []string{"useragents", "creationdates", "usernames"} {
		uids := make([]string, 0)
		values := make([]string, 0)

		csvFile, err := os.Open(fmt.Sprintf("./%s.csv", tableName))
		if err != nil {
			log.Fatalf("failed to open CSV file: %v", err)
		}
		defer csvFile.Close()

		reader := csv.NewReader(csvFile)
		// Skip the header row
		_, err = reader.Read()
		if err != nil {
			log.Fatalf("failed to read CSV header: %v", err)
		}
		records, err := reader.ReadAll()
		if err != nil {
			log.Fatalf("failed to read CSV file: %v", err)
		}

		for _, record := range records {
			if len(record) < 2 {
				continue
			}
			uids = append(uids, record[0])
			values = append(values, record[1])
		}

		table := mppj.NewTablePlain(uids, values)
		tables[sourceIDs[i]] = table
	}

	return tables
}

func MPPJ() {

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

	// Extracting tables from DB

	tables := extractTables(sourceIDs)

	for ds, table := range tables {
		fmt.Printf("Table of %s:\n", ds)
		fmt.Println(table)
		fmt.Println()
	}

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
