# app/src/main/assets/ — generated, not committed

The Gradle task `:app:generateSpikeFixtures` (auto-run before every build)
populates this directory:

```
sample.pdf                sample-multipage.pdf        # from core/testpdf (BSD-2-Clause)
lab/root-ca.crt.pem       lab/intermediate-ca.crt.pem
lab/ca-chain.pem          lab/device.crt.pem          lab/crl.pem
lab/device-test-key.pem   # THROWAWAY lab key — never a real device key
```

It shells out to `pqcsign-cli genpki` (module `apps/windows`), so a Go 1.27
toolchain must be on PATH when you build the APK. The set is regenerated only
when `lab/device-test-key.pem` is missing.

None of this is committed (`.gitignore`) — a private key, even a lab one, must
not enter git history (Rencana V1 §5.3, §9.3, §26). Real device keys are
generated on-device and wrapped by the Android Keystore in M5.
