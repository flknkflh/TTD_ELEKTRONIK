package id.example.pqcsign

import android.content.res.AssetManager
import android.os.Build
import id.example.pqcsign.core.CsrRequest
import id.example.pqcsign.core.SignOptions
import id.example.pqcsign.core.SigningEngine
import java.util.Locale

/**
 * On-device M1 proof (Rencana V1 §10.2, §25.3, §25.5): generate an ML-DSA-65
 * key on the phone, sign the bundled sample PDFs with the lab fixture
 * key/chain, verify against the embedded Root CA, and confirm a tampered PDF
 * is rejected. Produces a text report and keeps the signed sample PDF so it
 * can be exported and cross-verified on Windows with `pqcsign-cli verify`.
 *
 * The `lab/` assets — including `device-test-key.pem` — are throwaway test
 * fixtures that exist only in this debug APK. Real device keys are generated
 * on-device and wrapped by the Android Keystore (§12.2); that is M5.
 */
class SpikeRunner(private val assets: AssetManager) {

    data class Result(
        val passed: Boolean,
        val report: String,
        val signedSamplePdf: ByteArray?,
    )

    private fun asset(name: String) = assets.open(name).use { it.readBytes() }

    fun run(log: (String) -> Unit): Result {
        val sb = StringBuilder()
        fun line(s: String) { sb.append(s).append('\n'); log(s) }

        var pass = true
        fun check(name: String, ok: Boolean, detail: String = "") {
            if (!ok) pass = false
            line(String.format(Locale.US, "[%s] %-28s %s", if (ok) "PASS" else "FAIL", name, detail))
        }

        line("PQC PDF Sign V1 — on-device M1 spike")
        line("device: ${Build.MANUFACTURER} ${Build.MODEL}  abi: ${Build.SUPPORTED_ABIS.joinToString()}  api: ${Build.VERSION.SDK_INT}")
        line("")

        val samplePdf = asset("sample.pdf")
        val multiPdf = asset("sample-multipage.pdf")
        val rootPem = asset("lab/root-ca.crt.pem")
        val interPem = asset("lab/intermediate-ca.crt.pem")
        val chainPem = asset("lab/ca-chain.pem")
        val deviceKeyPem = asset("lab/device-test-key.pem")
        val crlPem = asset("lab/crl.pem")

        // 1. key generated on THIS device
        val t0 = System.nanoTime()
        val genKey = SigningEngine.generateKey()
        val genMs = (System.nanoTime() - t0) / 1_000_000
        val pubPem = SigningEngine.exportPublicKeyPem(genKey)
        check("keygen_on_device", genKey.isNotEmpty() && pubPem.isNotEmpty(),
            "PKCS#8 ${genKey.size} B in ${genMs} ms")

        // 2. CSR from the on-device key
        val csr = SigningEngine.createCsr(genKey, CsrRequest(commonName = "On-Device Spike", platform = "android"))
        check("csr_created", String(csr).contains("CERTIFICATE REQUEST"), "${csr.size} B PEM")

        // 3. sign the sample PDF (lab fixture key + chain)
        val ts = System.nanoTime()
        val signed = SigningEngine.signPdf(
            samplePdf, deviceKeyPem, chainPem,
            SignOptions(
                reason = "On-device M1 spike",
                signerName = "Android Spike Device",
                publicId = "sig_android_spike",
                verificationUrl = "https://verify.example.id/v/sig_android_spike",
                includeQr = true,
            ),
        )
        val signMs = (System.nanoTime() - ts) / 1_000_000
        val overhead = signed.size - samplePdf.size
        check("sign_sample_pdf", signed.size > samplePdf.size, "${signed.size} B (+$overhead) in ${signMs} ms")

        // 4. verify against the EMBEDDED Root CA
        val tv = System.nanoTime()
        val v = SigningEngine.verifyPdf(signed, rootPem, crlPem)
        val verifyMs = (System.nanoTime() - tv) / 1_000_000
        check("verify_explicit_root", v.valid, "valid=${v.valid} alg=${v.firstAlgorithm} in ${verifyMs} ms")
        check("algorithm_mldsa65", v.firstAlgorithm == "ML-DSA-65", v.firstAlgorithm)

        // 5. tampered PDF must fail
        val tampered = signed.copyOf()
        tampered[tampered.size / 2] = (tampered[tampered.size / 2].toInt() xor 0xFF).toByte()
        val tv2 = SigningEngine.verifyPdf(tampered, rootPem, crlPem)
        check("tampered_pdf_rejected", !tv2.valid, "valid=${tv2.valid} (want false)")

        // 6. wrong root must fail (reuse intermediate PEM as a bogus anchor)
        val vWrong = SigningEngine.verifyPdf(signed, interPem, null)
        check("wrong_root_rejected", !vWrong.valid, "valid=${vWrong.valid} (want false)")

        // 7. multi-page PDF
        val signedMulti = SigningEngine.signPdf(
            multiPdf, deviceKeyPem, chainPem,
            SignOptions(signerName = "Android Spike Device", publicId = "sig_android_multi", includeQr = true),
        )
        val vMulti = SigningEngine.verifyPdf(signedMulti, rootPem, crlPem)
        check("multipage_sign_verify", signedMulti.size > multiPdf.size && vMulti.valid,
            "signed ${signedMulti.size} B, valid=${vMulti.valid}")

        line("")
        line("verification JSON (sample):")
        line(v.pretty())
        line("")
        line(if (pass) "SPIKE PASSED" else "SPIKE FAILED")
        line("Use \"Simpan signed.pdf\" to export and cross-check on Windows:")
        line("  pqcsign-cli verify --in signed.pdf --root root-ca.crt.pem --intermediate intermediate-ca.crt.pem --crl crl.pem")

        return Result(pass, sb.toString(), if (pass || signed.isNotEmpty()) signed else null)
    }
}
