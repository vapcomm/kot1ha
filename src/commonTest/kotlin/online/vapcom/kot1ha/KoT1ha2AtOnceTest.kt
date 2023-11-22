/*
 * (c) VAP Communications Group, 2023
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package online.vapcom.kot1ha

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Tests of t1ha2 at once variant
 */
@OptIn(ExperimentalStdlibApi::class)
class KoT1ha2AtOnceTest {

    @Test
    fun smokeTests() {
        // generated test data on
        // https://asecuritysite.com/encryption/smh_t1ha
        assertEquals("A0A7281AA08ADD7B", t1ha2AtOnceHex("test".encodeToByteArray()))
        assertEquals("4B0B7D3CDE9FBCE6", t1ha2AtOnceHex("0".encodeToByteArray()))
        assertEquals("2B9431FA5018CCCB", t1ha2AtOnceHex("0000000000000000".encodeToByteArray()))
        assertEquals("EC5FC94B84DF3B87", t1ha2AtOnceHex("1000000000000000".encodeToByteArray()))
    }

    /*
     * Tests from t1ha_selfcheck.c split into different functions.
     * C-style comments show original test cases.
     * Expected values arrays are taken from t1ha_refval_2atonce[] from t1ha2_selfcheck.c
     */

    // original t1ha_test_pattern from t1ha_selfcheck.c
    private val testPattern: ByteArray = byteArrayOf(
        0, 1, 2, 3, 4, 5, 6, 7, 0xFF.toByte(), 0x7F, 0x3F,
        0x1F, 0xF, 8, 16, 32, 64, 0x80.toByte(), 0xFE.toByte(), 0xFC.toByte(), 0xF8.toByte(), 0xF0.toByte(),
        0xE0.toByte(), 0xC0.toByte(), 0xFD.toByte(), 0xFB.toByte(),
        0xF7.toByte(), 0xEF.toByte(), 0xDF.toByte(), 0xBF.toByte(), 0x55, 0xAA.toByte(), 11,
        17, 19, 23, 29, 37, 42, 43,
        'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(), 'd'.code.toByte(),
        'e'.code.toByte(), 'f'.code.toByte(), 'g'.code.toByte(), 'h'.code.toByte(),
        'i'.code.toByte(), 'j'.code.toByte(), 'k'.code.toByte(), 'l'.code.toByte(),
        'm'.code.toByte(), 'n'.code.toByte(), 'o'.code.toByte(), 'p'.code.toByte(),
        'q'.code.toByte(), 'r'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(),
        'u'.code.toByte(), 'v'.code.toByte(), 'w'.code.toByte(), 'x'.code.toByte()
    )

    @Test
    fun selfCheckBase() {
        assertEquals(64, testPattern.size)

        /* empty-zero */
        assertEquals("0000000000000000", t1ha2AtOnceHex(ByteArray(0), 0UL))
        /* empty-all1 */
        assertEquals("772C7311BE32FF42", t1ha2AtOnceHex(ByteArray(0), 0UL.inv()))
        /* bin64-zero */
        assertEquals("444753D23F207E03", t1ha2AtOnceHex(testPattern, 0UL))
    }

    private val oneBitExpected = arrayOf(
        0x71F6DF5DA3B4F532UL, 0x555859635365F660UL, 0xE98808F1CD39C626UL, 0x2EB18FAF2163BB09UL,
        0x7B9DD892C8019C87UL, 0xE2B1431C4DA4D15AUL, 0x1984E718A5477F70UL, 0x08DD17B266484F79UL,
        0x4C83A05D766AD550UL, 0x92DCEBB131D1907DUL, 0xD67BC6FC881B8549UL, 0xF6A9886555FBF66BUL,
        0x6E31616D7F33E25EUL, 0x36E31B7426E3049DUL, 0x4F8E4FAF46A13F5FUL, 0x03EB0CB3253F819FUL,
        0x636A7769905770D2UL, 0x3ADF3781D16D1148UL, 0x92D19CB1818BC9C2UL, 0x283E68F4D459C533UL,
        0xFA83A8A88DECAA04UL, 0x8C6F00368EAC538CUL, 0x7B66B0CF3797B322UL, 0x5131E122FDABA3FFUL,
        0x6E59FF515C08C7A9UL, 0xBA2C5269B2C377B0UL, 0xA9D24FD368FE8A2BUL, 0x22DB13D32E33E891UL,
        0x7B97DFC804B876E5UL, 0xC598BDFCD0E834F9UL, 0xB256163D3687F5A7UL, 0x66D7A73C6AEF50B3UL,
        0x25A7201C85D9E2A3UL, 0x911573EDA15299AAUL, 0x5C0062B669E18E4CUL, 0x17734ADE08D54E28UL,
        0xFFF036E33883F43BUL, 0xFE0756E7777DF11EUL, 0x37972472D023F129UL, 0x6CFCE201B55C7F57UL,
        0xE019D1D89F02B3E1UL, 0xAE5CC580FA1BB7E6UL, 0x295695FB7E59FC3AUL, 0x76B6C820A40DD35EUL,
        0xB1680A1768462B17UL, 0x2FB6AF279137DADAUL, 0x28FB6B4366C78535UL, 0xEC278E53924541B1UL,
        0x164F8AAB8A2A28B5UL, 0xB6C330AEAC4578ADUL, 0x7F6F371070085084UL, 0x94DEAD60C0F448D3UL,
        0x99737AC232C559EFUL, 0x6F54A6F9CA8EDD57UL, 0x979B01E926BFCE0CUL, 0xF7D20BC85439C5B4UL,
        0x64EDB27CD8087C12UL, 0x11488DE5F79C0BE2UL, 0x25541DDD1680B5A4UL, 0x8B633D33BE9D1973UL,
        0x404A3113ACF7F6C6UL, 0xC59DBDEF8550CD56UL, 0x039D23C68F4F992CUL
    )

    @Test
    fun selfCheckOneBitSeed() {
        assertEquals(64, testPattern.size)
        assertEquals(63, oneBitExpected.size)

        /* bin%i-1p%i */
        var seed = 1UL
        for (i in 1..63) {
            assertEquals(oneBitExpected[i - 1].toHexString(HexFormat.UpperCase), t1ha2AtOnceHex(testPattern.copyOfRange(0, i), seed))
            seed = seed shl 1
        }
    }

    private val zeroBitExpected = arrayOf(
        0x5BBB48E4BDD6FD86UL, 0x41E312248780DF5AUL, 0xD34791CE75D4E94FUL, 0xED523E5D04DCDCFFUL,
        0x7A6BCE0B6182D879UL, 0x21FB37483CAC28D8UL, 0x19A1B66E8DA878ADUL
    )

    @Test
    fun selfCheckZeroBitSeed() {
        assertEquals(64, testPattern.size)
        assertEquals(7, zeroBitExpected.size)

        /* align%i_F%i */
        var seed = 0UL.inv()
        for (i in 1..7) {
            seed = seed shl 1
            assertEquals(
                zeroBitExpected[i - 1].toHexString(HexFormat.UpperCase),
                t1ha2AtOnceHex(testPattern.copyOfRange(i, testPattern.size), seed)
            )
        }
    }

    private val longPatternExpected = arrayOf(
        0x6F804C5295B09ABEUL,
        0x2A4BE5014115BA81UL, 0xA678ECC5FC924BE0UL, 0x50F7A54A99A36F59UL,
        0x0FD7E63A39A66452UL, 0x5AB1B213DD29C4E4UL, 0xF3ED80D9DF6534C5UL, 0xC736B12EF90615FDUL
    )

    @Test
    fun selfCheckLongPattern() {
        assertEquals(64, testPattern.size)
        assertEquals(8, longPatternExpected.size)

        val longPattern = ByteArray(512) { it.toByte() }

        /* long-%05i */
        val seed = 0UL.inv() shl 7  // in the original test seed's value was calculated on the previous test /* align%i_F%i */
        for (i in 0..7) {
            assertEquals(
                longPatternExpected[i].toHexString(HexFormat.UpperCase),
                t1ha2AtOnceHex(longPattern.copyOfRange(i, i + 128 + i * 17), seed)
            )
        }
    }

}

/**
 * Calculate 64 bit t1ha2 hash of a given byte array and return Hex-string of a result
 */
@OptIn(ExperimentalStdlibApi::class)
fun t1ha2AtOnceHex(data: ByteArray, seed: ULong = 0UL) = koT1ha2AtOnce(data, seed).toHexString(HexFormat.UpperCase)
