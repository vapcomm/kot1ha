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
class KoT1ha2AtOnceTest {

    @Test
    fun smokeTests() {
        // generated test data on
        // https://asecuritysite.com/encryption/smh_t1ha
        assertEquals("a0a7281aa08add7b", t1ha2AtOnceHex("test".encodeToByteArray()))
        assertEquals("4b0b7d3cde9fbce6", t1ha2AtOnceHex("0".encodeToByteArray()))
        assertEquals("2b9431fa5018cccb", t1ha2AtOnceHex("0000000000000000".encodeToByteArray()))
        assertEquals("ec5fc94b84df3b87", t1ha2AtOnceHex("1000000000000000".encodeToByteArray()))
    }

    //TODO: data length 31, 32 bytes for edge cases in t1ha2 internal loop

    //TODO: tests on all 1..31 bytes data sizes

    @Test
    fun originalSelfCheck() {
        // original t1ha_test_pattern from t1ha_selfcheck.c
        val testPattern: ByteArray = byteArrayOf(
            0,    1,    2,    3,    4,    5,    6,    7,  0xFF.toByte(), 0x7F, 0x3F,
            0x1F, 0xF,  8,    16,   32,   64,   0x80.toByte(), 0xFE.toByte(), 0xFC.toByte(), 0xF8.toByte(), 0xF0.toByte(),
            0xE0.toByte(), 0xC0.toByte(), 0xFD.toByte(), 0xFB.toByte(),
            0xF7.toByte(), 0xEF.toByte(), 0xDF.toByte(), 0xBF.toByte(), 0x55, 0xAA.toByte(), 11,
            17,   19,   23,   29,   37,   42,   43,
            'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(), 'd'.code.toByte(),
            'e'.code.toByte(), 'f'.code.toByte(), 'g'.code.toByte(), 'h'.code.toByte(),
            'i'.code.toByte(), 'j'.code.toByte(), 'k'.code.toByte(), 'l'.code.toByte(),
            'm'.code.toByte(), 'n'.code.toByte(), 'o'.code.toByte(), 'p'.code.toByte(),
            'q'.code.toByte(), 'r'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(),
            'u'.code.toByte(), 'v'.code.toByte(), 'w'.code.toByte(), 'x'.code.toByte()
        )

        assertEquals(64, testPattern.size)

        assertEquals("0000000000000000", t1ha2AtOnceHex(ByteArray(0), 0UL))
    }
}
