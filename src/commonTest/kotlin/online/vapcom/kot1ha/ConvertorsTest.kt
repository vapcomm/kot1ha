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
 * Tests of ByteArray <-> ULong converters
 */
class ConvertorsTest {

    @Test
    fun littleEndianToULongZero() {
        val data = ByteArray(8) { 0 }
        assertEquals(0UL, littleEndianToULong(data, 0))
    }

    @Test
    fun littleEndianToULongOne() {
        val data = "0100000000000000".decodeHex()
        assertEquals(1UL, littleEndianToULong(data, 0))
    }

    @Test
    fun littleEndianToULongMinusOne() {
        val data = "FFFFFFFFFFFFFFFF".decodeHex()
        assertEquals(0xFFFFFFFFFFFFFFFFUL, littleEndianToULong(data, 0))
    }

    @Test
    fun littleEndianToULongCheckEndian() {
        val data = "1234567890ABCDEF".decodeHex()
        assertEquals(0xEFCDAB9078563412UL, littleEndianToULong(data, 0))
    }

    @Test
    fun littleEndianToULongOneTwo() {
        val data = "01000000000000000200000000000000".decodeHex()
        assertEquals(1UL, littleEndianToULong(data, 0))
        assertEquals(2UL, littleEndianToULong(data, 8))
    }

    @Test
    fun littleEndianToULongMiddle() {
        val data = "1234567890ABCDEF1234567890ABCDEF".decodeHex()
        assertEquals(0xCDAB9078563412EFUL, littleEndianToULong(data, 7))
    }


    @Test
    fun tail1() {
        val data = "12".decodeHex()
        assertEquals(0x12UL, leTail64(data, 0, 1))
    }

    @Test
    fun tail2() {
        val data = "1234".decodeHex()
        assertEquals(0x3412UL, leTail64(data, 0, 2))
    }

    @Test
    fun tail3() {
        val data = "123456".decodeHex()
        assertEquals(0x563412UL, leTail64(data, 0, 3))
    }

    @Test
    fun tail4() {
        val data = "12345678".decodeHex()
        assertEquals(0x78563412UL, leTail64(data, 0, 4))
    }

    @Test
    fun tail5() {
        val data = "1234567890".decodeHex()
        assertEquals(0x9078563412UL, leTail64(data, 0, 5))
    }

    @Test
    fun tail6() {
        val data = "1234567890AB".decodeHex()
        assertEquals(0xAB9078563412UL, leTail64(data, 0, 6))
    }

    @Test
    fun tail7() {
        val data = "1234567890ABCD".decodeHex()
        assertEquals(0xCDAB9078563412UL, leTail64(data, 0, 7))
    }

    @Test
    fun tail7Off1() {
        val data = "1234567890ABCDEF01".decodeHex()
        assertEquals(0xEFCDAB90785634UL, leTail64(data, 1, 7))
    }

    @Test
    fun tail8() {
        val data = "1234567890ABCDEF".decodeHex()
        // it's the same as littleEndianToULong()
        assertEquals(0xEFCDAB9078563412UL, leTail64(data, 0, 8))
    }

    @Test
    fun tail9() {
        val data = "1234567890ABCDEF01".decodeHex()
        // tail can't be more than 8 bytes, for simplicity only 3 less valued bits of tail is used
        assertEquals(0x12UL, leTail64(data, 0, 9))
    }

    @Test
    fun uLongToBigEndian() {
        assertEquals("efcdab9078563412", uLongToBigEndian(0xEFCDAB9078563412UL).toHexString())
        assertEquals("0102030405060708", uLongToBigEndian(0x0102030405060708UL).toHexString())
    }

}
