# research/

Notes and **clones of reference repositories**. Nothing here is part of the
product build and nothing here is committed (see `.gitignore`).

```sh
git clone https://github.com/digitorus/pdfsign.git
cd pdfsign && git checkout 39f87fec7e33af3e3daa77f6fa86820b813036d5 && go test ./...

cd ..
git clone https://github.com/digitorus/pdfsigner.git
cd pdfsigner && git checkout 54fd26fee2ff9799e3d07410a9a244075bdc4328
```

* `pdfsign` (BSD-2-Clause) — the actual dependency, pinned as `v1.0.0-rc2`.
  Patch only for portability / binding / PDF bugs / integration security, each
  with a test and an upstream diff note. Never touch the ML-DSA implementation.
* `pdfsigner` (GPLv3) — **read only.** Study its REST/queue/verify patterns.
  Do not copy source into the product.

No private keys live here.
