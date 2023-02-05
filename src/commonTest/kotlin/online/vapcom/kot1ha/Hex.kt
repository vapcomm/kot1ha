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

/**
 * Decode Hex-string to ByteArray.
 *
 * Taken from: https://stackoverflow.com/a/66614516/10085047
 */
fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

/**
 * Encode ByteArray to Hex-string
 *
 * Taken from: https://stackoverflow.com/a/52225984/10085047 (Sven Sep 20, 2019 at 10:18)
 */
fun ByteArray.toHexString() = joinToString("") {
    (0xFF and it.toInt()).toString(16).padStart(2, '0')
}

/**
 * Calculate 64 bit t1ha2 hash of given byte array and return Hex-string of result
 */
fun t1ha2AtOnceHex(data: ByteArray, seed: ULong = 0UL) = koT1ha2AtOnce(data, seed).toHexString()
