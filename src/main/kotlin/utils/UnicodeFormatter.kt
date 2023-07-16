package utils

object UnicodeFormatter {
    // Returns hex String representation of byte b
    fun byteToHex(b: Byte): String {
        val hexDigit = charArrayOf(
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        )
        val array = charArrayOf(hexDigit[b.toInt() shr 4 and 0x0f], hexDigit[b.toInt() and 0x0f])
        return String(array)
    }

    // Returns hex String representation of char c
    fun charToHex(c: Char): String {
        val hi = (c.code ushr 8).toByte()
        val lo = (c.code and 0xff).toByte()
        return byteToHex(hi) + byteToHex(lo)
    }
}
