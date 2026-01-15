package mppj

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// TablePlain represents a plain table with UID as key and value as string.
// It is the protocol input type for data sources.
type TablePlain map[string]string

// TableRow represents a single row in a plain table.
type TableRow struct {
	uid string
	val string
}

// EncRow represents a single encrypted row with encrypted UID and encrypted value(s).
type EncRow struct {
	Cuid *Ciphertext
	Cval []*Ciphertext
}

// EncTable represents an encrypted table as a slice of encrypted rows.
// It is the output type for the data source and the input type for the helper.
type EncTable []EncRow

// EncRowWithHint represents a single encrypted row after processing by the helper.
type EncRowWithHint struct {
	Cnyme   Ciphertext
	CVal    SymmetricCiphertext
	CValKey Ciphertext
	CHint   Ciphertext
}

// EncTableWithHint represents an encrypted table after processing by the helper.
// It is the output type for the helper and the input type for the receiver.
type EncTableWithHint []EncRowWithHint

// JoinTable represents the final joined table produced by the receiver.
// It is the output type for the receiver.
type JoinTable struct {
	sourceids []PartyID
	values    [][]string
}

// Len returns the number of rows in the joined table.
func (t JoinTable) Len() int {
	return len(t.values)
}

// MarshalBinary serializes an EncRow into a byte slice.
func (er EncRow) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	cuidBytes, err := er.Cuid.Serialize()
	if err != nil {
		return nil, err
	}
	if len(er.Cval) > 1 {
		return nil, fmt.Errorf("multiple ciphertext values not supported")
	}
	cvalBytes, err := er.Cval[0].Serialize()
	if err != nil {
		return nil, err
	}
	buf.Write(cuidBytes)
	buf.Write(cvalBytes)
	return buf.Bytes(), nil
}

// NewTablePlain creates a new Table from a UID list and optional values.
func NewTablePlain(uids []string, values []string) TablePlain {

	var newTable = make(map[string]string, len(uids))

	for i, uid := range uids {
		if i < len(values) {
			newTable[uid] = values[i]
		}
	}
	return TablePlain(newTable)
}

// NewJoinTable creates a new empty JoinTable for the given source IDs.
func NewJoinTable(sourceIDs []PartyID) JoinTable {

	var newTable = JoinTable{
		sourceids: make([]PartyID, len(sourceIDs)),
		values:    make([][]string, 0),
	}
	copy(newTable.sourceids, sourceIDs)
	return newTable
}

// Insert adds a new row to the joined table with the given values mapped by source ID.
func (t *JoinTable) Insert(values map[PartyID]string) error {
	row := make([]string, len(t.sourceids))
	for sourceID, value := range values {
		col := slices.Index(t.sourceids, sourceID)
		if col == -1 {
			return fmt.Errorf("source ID %s not found", sourceID)
		}
		row[col] = value
	}
	t.values = append(t.values, row)
	return nil
}

// WriteTo writes the joined table to a CSV writer.
func (t JoinTable) WriteTo(w *csv.Writer) error {
	sourceIDsStr := make([]string, len(t.sourceids))
	for i, sid := range t.sourceids {
		sourceIDsStr[i] = string(sid)
	}
	if err := w.Write(sourceIDsStr); err != nil {
		return err
	}
	for _, row := range t.values {
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return nil
}

// String returns the joined table as a CSV-formatted string.
func (t JoinTable) String() string {
	// write as CSV
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	err := t.WriteTo(w)
	if err != nil {
		return fmt.Sprintf("error writing table: %v", err)
	}
	return buf.String()
}

// Equal checks both the keys and the values for plain tables.
func (t1 *TablePlain) Equal(t2 *TablePlain) bool {
	if len(*t1) != len(*t2) {
		return false
	}

	for key, value1 := range *t1 {
		value2, exists := (*t2)[key]
		if !exists {
			return false
		}
		if value1 != value2 {
			return false
		}
	}

	return true
}

// EqualContents checks only the contents of the joined tables, ignoring the order of rows.
func (t1 *JoinTable) EqualContents(t2 *JoinTable) bool {

	if t1.Len() != t2.Len() {
		return false
	}

	for sid := range t1.sourceids {
		if t1.sourceids[sid] != t2.sourceids[sid] {
			return false
		}
	}

	t1Vals := make(map[string]struct{})
	for _, row := range t1.values {
		rowKey := strings.Join(row, "|") // TODO: more robust way to determine equality
		t1Vals[rowKey] = struct{}{}
	}

	for _, row := range t2.values {
		rowKey := strings.Join(row, "|")
		if _, exists := t1Vals[rowKey]; !exists {
			return false
		}
	}

	return true
}

// IntersectPlain performs a join on plain tables
func IntersectPlain(tables map[PartyID]TablePlain, sources []PartyID) JoinTable {

	// groups the values by uids
	partJoin := make(map[string]map[PartyID]string)
	for sourceID, table := range tables {
		for uid, val := range table {
			if _, exists := partJoin[uid]; !exists {
				partJoin[uid] = make(map[PartyID]string)
			}
			partJoin[uid][sourceID] = val
		}
	}

	joined := NewJoinTable(sources)
	for _, vals := range partJoin {
		if len(vals) == len(tables) {
			joined.Insert(vals)
		}
	}
	return joined
}

// String returns the plain table as a formatted string.
func (t TablePlain) String() string {
	var s string
	s += "UID " + " " + " Value\n"
	s += "---------------------\n"

	for uid, value := range t {
		s += uid + " "
		s += value + " "

		s += "\n"
	}

	return s
}

// GenTestTables generates test tables for the given source IDs with specified number of rows and intersection size.
func GenTestTables(sourceIDs []PartyID, nRows, intersectionSize int) map[PartyID]TablePlain {
	intersection := make([]string, intersectionSize)
	for i := 0; i < intersectionSize; i++ {
		intersection[i] = fmt.Sprintf("join_key_%d", i)
	}
	tables := make(map[PartyID]TablePlain)
	for _, sourceID := range sourceIDs {
		tables[sourceID] = GenTestTable(sourceID, nRows, intersection)
	}
	return tables
}

// GenTestTable generates a test table for a given source ID with specified number of rows and intersection UIDs.
func GenTestTable(sourceId PartyID, nRows int, intersection []string) TablePlain {
	table := make(TablePlain)
	v := 0
	// Add intersection rows
	for _, uid := range intersection {
		table[uid] = "value_" + strconv.Itoa(v)
		v++
	}
	// Add non-intersection rows
	for i := 0; i < nRows-len(intersection); i++ {
		uid := fmt.Sprintf("%s_%d", sourceId, i)
		table[uid] = "non_join_value_" + strconv.Itoa(v)
		v++
	}
	return table
}
