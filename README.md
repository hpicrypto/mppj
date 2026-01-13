# MPPJ-Go: a Go Implementation of the DH-MPPJ Protocol

This package implement the FD-MPPJ protocol, as proposed in the paper "Multi-party Private
Joins" by by Anja Lehmann, Christian Mouchet and Andrey Sidorenko, PETS 2026. It implement
this protocol over the P-256 elliptic curve.

## Synopsis

For each party, this package provides an implementation as a type: `mppj.Source`,
`mppj.Helper` and `mppj.Receiver`. Each type can be instantiated from public parameters
and provide the main cryptographic operation as public methods.

The protocol has two rounds, so each type has one main method which correspond to its
local operation in the protocol:
- `mppj.Source.Prepare` encrypts the source's data towards the receiver's public key.
- `mppj.Helper.Convert` takes as input all the sources' encrypted data tables, and
  computes an encrypted *joined* table
- `mppj.Receiver.JoinTables` decrypts the joined tables and extract the join.

Each operation has a channel-based counterpart which enables each party to process the
tables in a streaming fashion. The streamed and the non-streamed methods enable processing
over multiple cores via a parameterizable number of goroutines.

See the `examples/minimal/main.go` file for a minimal working program demonstrating the
use of the types.

## Package Structure

- `party_datasource.go`: the source-related operations.
- `party_helper.go`: the helper-related operations.
- `party_receiver.go`: the receiver-related operations.
- `group.go` a group abstraction for ElGamal.
- `encryption.go` the PKE / SE functionality
- `prf.go` the Hash-DH OPRF (for ElGamal PKE)
- `table.go` some basic types (plaintext table, joined table) and functions for tables
- `mppj_test.go` some end-to-end tests.
- `benchmark_test.go` some micro-benchmarks for individual operations.
- `api` a gRPC-based service for the helper (server) and source/receiver (clients).
- `cmd` the executables (main packages) for the sources/helper/receiver.

## Current Limitations

- The number of sources is limited to 256, as it encode the origin table over a single byte.
- The values are also assumed to be smaller than 30 bytes, for encoding them as group
  elements in a decodable way.
- The large-values extension proposed of the paper is not yet implemented.
- The parties can send any number of rows and the implementation does not add any dummy
  value to pad to a given number. 

## Security

This repository contains a prototype implementation of the MPPJ protocol. This is for
academic research purposes and should not be considered production-ready. Notably, the
code was not externally audited and includes several non-constant-time algorithms.
