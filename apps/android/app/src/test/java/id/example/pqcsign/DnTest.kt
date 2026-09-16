package id.example.pqcsign

import id.example.pqcsign.app.Dn
import org.junit.Assert.assertEquals
import org.junit.Test

class DnTest {
    @Test fun readsPlainAttributes() {
        val dn = "CN=Budi Santoso,O=Dinas Kominfo,C=ID"
        assertEquals("Budi Santoso", Dn.part(dn, "CN"))
        assertEquals("Dinas Kominfo", Dn.part(dn, "O"))
    }

    /** The case the escaping exists for: a degree puts a comma in the value. */
    @Test fun keepsAnEscapedComma() {
        val dn = "CN=Dr. Siti Rahayu\\, M.Kom,O=Universitas,C=ID"
        assertEquals("Dr. Siti Rahayu, M.Kom", Dn.part(dn, "CN"))
        assertEquals("Universitas", Dn.part(dn, "O"))
    }

    @Test fun unescapesOtherEscapes() {
        assertEquals("A+B", Dn.part("CN=A\\+B,O=X", "CN"))
    }

    @Test fun missingAttributeIsEmpty() {
        assertEquals("", Dn.part("CN=Budi,C=ID", "OU"))
    }

    /**
     * The regression this file exists for: a subject that parses must never
     * throw. A halved backslash turns the unescape pattern into "\(.)", whose
     * unmatched ")" raises PatternSyntaxException on the UI thread - which
     * force-closed the app the moment a valid signature was rendered.
     */
    @Test fun neverThrows() {
        for (s in listOf("", "CN=Budi", "CN=Budi,O=X", "garbage", "CN=A\\,B,O=Y")) {
            Dn.part(s, "CN")
            Dn.part(s, "O")
        }
    }
}
