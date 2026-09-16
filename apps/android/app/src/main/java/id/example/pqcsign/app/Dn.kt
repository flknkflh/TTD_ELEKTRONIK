package id.example.pqcsign.app

/**
 * Reads one attribute out of an X.509 distinguished name.
 *
 * A DN escapes a comma inside a value as "\,", so splitting on the first comma
 * truncates any name carrying a degree. Consume escaped characters, then
 * unescape. This lives here rather than inside the activity so the escaping is
 * covered by a unit test: a mangled backslash still compiles and only blows up
 * at runtime, on the main thread, while a verdict is being rendered.
 */
object Dn {
    fun part(subject: String, key: String): String =
        Regex("$key=((?:\\\\.|[^,])*)").find(subject)?.groupValues?.get(1)
            ?.replace(Regex("\\\\(.)")) { it.groupValues[1] }.orEmpty()
}
