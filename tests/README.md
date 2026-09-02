# tests/

* `fixtures/` — sample inputs (`sample.pdf` is the digitorus/pdfsign
  `testfile12.pdf`, BSD-2-Clause).
* `integration/` — cross-module tests once `server/` exists (M6).
* `e2e/` — Windows ↔ Android ↔ server acceptance runs (M8, §25).

Today the executable acceptance coverage lives in `core/spike` (run
`cd core && go test ./spike/ -v`): local sign, verify against the explicit
Root CA, tampered-PDF rejection, wrong-Root rejection, CSR proof-of-possession,
key/cert match.
