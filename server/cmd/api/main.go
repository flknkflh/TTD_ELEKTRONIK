// Command api is the PQC PDF Sign V1 receiver server (Rencana V1 §17, §22).
//
// It accepts already-signed PDFs, re-verifies them strictly against the
// configured Root CA, stores metadata + object, and serves the public
// verifier. It has NO endpoint that signs a PDF on a user's behalf
// (Rencana V1 §1, §17.5). Implementation lands in milestone M6; this is a
// placeholder so the module and skeleton build.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "pqc-pdf-sign receiver API: not implemented yet (milestone M6)")
	os.Exit(1)
}
