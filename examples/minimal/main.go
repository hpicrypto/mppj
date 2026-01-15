// Minimal, local example of using the MPPJ library to perform a private join among three parties.
package main

import (
	"fmt"

	"github.com/hpicrypto/mppj"
)

func main() {

	// Session setup
	sourceIDs := []mppj.PartyID{"s1", "s2", "s3"}
	rsk, rpk := mppj.KeyGen()
	sess := must(mppj.NewSession(sourceIDs, "helper", "receiver", rpk))

	// Parties' initialization (sources have no individual state)
	source, helper, receiver := mppj.NewDataSource(sess), mppj.NewHelper(sess), mppj.NewReceiver(sess, rsk)

	// Data sources prepare their tables
	encTables := map[mppj.PartyID]mppj.EncTable{
		sourceIDs[0]: must(source.Prepare(mppj.TablePlain{"a": "1", "b": "o", "d": "x"})),
		sourceIDs[1]: must(source.Prepare(mppj.TablePlain{"a": "2", "b": "o", "d": "y"})),
		sourceIDs[2]: must(source.Prepare(mppj.TablePlain{"a": "3", "c": "o", "d": "z"})),
	}

	// Helper converts the tables
	joinedTables := must(helper.Convert(encTables))

	// Receiver extracts the joined table
	fmt.Println(must(receiver.JoinTables(joinedTables)))
}

func must[T any](arg T, err error) T {
	if err != nil {
		panic(err)
	}
	return arg
}
