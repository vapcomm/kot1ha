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

/*
 * This t1ha2 implementation based on t1ha2 main sources: https://github.com/erthink/t1ha/src/t1ha2.c
 */

// magic primes
private const val PRIME_0 = 0xEC99BF0D8372CAABUL
private const val PRIME_1 = 0x82434FE90EDCEF39UL
private const val PRIME_2 = 0xD4F06DB99D67BE4BUL
private const val PRIME_3 = 0xBD9CACC22C6E9571UL
private const val PRIME_4 = 0x9C06FAF4D023E3ABUL
private const val PRIME_5 = 0xC060724A8424F345UL
private const val PRIME_6 = 0xCB5AF53AE3AAAC31UL

/**
 * Return t1ha2 64 bits (8 bytes) hash of data with given seed
 */
fun koT1ha2AtOnce(data: ByteArray, seed: ULong = 0UL): ByteArray {
    var length: ULong = data.size.toULong()

    // We open t1ha_state256_t union to separate 4 vars

    // init_ab(&state, seed, length);
    var a: ULong = seed
    var b: ULong = length

    var c: ULong = 0UL
    var d: ULong = 0UL

    var off = 0

    if (length > 32UL) {
        // init_cd(&state, seed, length);
        c = rot64(length, 23) + seed.inv()  // c = rot64(y, 23) + ~x;
        d = length.inv() + rot64(seed, 19)  // d = ~y + rot64(x, 19);

        // T1HA2_LOOP(le, unaligned, &state, data, length);
        val lastOff = data.size - 31
        do {
            val w0 = littleEndianToULong(data, off)             // const uint64_t w0 = fetch64_le_unaligned(v + 0);
            val w1 = littleEndianToULong(data, off + 8)     // const uint64_t w1 = fetch64_le_unaligned(v + 1);
            val w2 = littleEndianToULong(data, off + 16)    // const uint64_t w2 = fetch64_le_unaligned(v + 2);
            val w3 = littleEndianToULong(data, off + 24)    // const uint64_t w3 = fetch64_le_unaligned(v + 3);

            val d02 = w0 + rot64(w2 + d, 56)    // const uint64_t d02 = w0 + rot64(w2 + s->n.d, 56);
            val c13 = w1 + rot64(w3 + c, 19)    // const uint64_t c13 = w1 + rot64(w3 + s->n.c, 19);

            d = d xor (b + rot64(w1, 38))   // s->n.d ^= s->n.b + rot64(w1, 38);
            c = c xor (a + rot64(w0, 57))   // s->n.c ^= s->n.a + rot64(w0, 57);
            b = b xor (PRIME_6 * (c13 + w2))    // s->n.b ^= prime_6 * (c13 + w2);
            a = a xor (PRIME_5 * (d02 + w3))    //  s->n.a ^= prime_5 * (d02 + w3);

            off += 32
        } while (off < lastOff)

        // squash(&state);
        a = a xor (PRIME_6 * (c + rot64(d, 23)))    // s->n.a ^= prime_6 * (s->n.c + rot64(s->n.d, 23));
        b = b xor (PRIME_5 * (rot64(c, 19) + d))    // s->n.b ^= prime_5 * (rot64(s->n.c, 19) + s->n.d);

        length = length and 31UL
    }

    // T1HA2_TAIL_AB(le, unaligned, &state, data, length);
    // const uint64_t *v = (const uint64_t *)data;
    // здесь data стоит на следующий блок, т.е. наш off показывает куда надо
    //TODO: переделать интервалы на length % 8, чтобы упростить сравнения на 0,1,2,3 и больше
    // исходник считает в байтах, но пользуется uint64_t *, т.е. v++ идёт по 8 байтным словам.
    // Мы работаем в длинах, поэтому быстрее будет посчитать сколько 8-байтных слов осталось в буфере
    
    val result = when (length) {
        in 17UL..24UL -> {
            // mixup64(&s->n.b, &s->n.a, fetch64_le_unaligned(v++), prime_3);
            // mixup64(&s->n.a, &s->n.b, fetch64_le_unaligned(v++), prime_2);
            // mixup64(&s->n.b, &s->n.a, tail64_##ENDIANNES##_##ALIGNESS(v, len), prime_1);
            // final64(s->n.a, s->n.b);
            0UL
        }

        in 9UL..16UL -> {
            // mixup64(&s->n.a, &s->n.b, fetch64_le_unaligned(v++), prime_2);
            // mixup64(&s->n.b, &s->n.a, tail64_##ENDIANNES##_##ALIGNESS(v, len), prime_1);
            // final64(s->n.a, s->n.b);
            0UL
        }

        in 1UL..8UL -> {
            // mixup64(&s->n.b, &s->n.a, tail64_##ENDIANNES##_##ALIGNESS(v, len), prime_1);
            // final64(s->n.a, s->n.b);
            0UL
        }

        0UL -> {
            // final64(s->n.a, s->n.b);
            0UL
        }

        else -> { // 25..31, it can't be >=32
            // mixup64(&s->n.a, &s->n.b, fetch64_le_unaligned(v++), prime_4);
/*
            static void mixup64(uint64_t *a, uint64_t *b, uint64_t v, uint64_t prime) {
              uint64_t h;
              *a ^= mul_64x64_128(*b + v, prime, &h);
              *b += h;
            }
 */
            var v = littleEndianToULong(data, off)
            a = a xor ((b + v) * PRIME_4)
            b += multiplyHigh(b + v, PRIME_4)
            off += 8

            // mixup64(&s->n.b, &s->n.a, fetch64_le_unaligned(v++), prime_3);
            v = littleEndianToULong(data, off)
            b = b xor ((a + v) * PRIME_3)
            a += multiplyHigh(a + v, PRIME_3)
            off += 8

            // mixup64(&s->n.a, &s->n.b, fetch64_le_unaligned(v++), prime_2);
            v = littleEndianToULong(data, off)
            a = a xor ((b + v) * PRIME_2)
            b += multiplyHigh(b + v, PRIME_2)
            off += 8

            // mixup64(&s->n.b, &s->n.a, tail64_##ENDIANNES##_##ALIGNESS(v, len), prime_1);
            v = leTail64(data, off, length.toInt())
            b = b xor ((a + v) * PRIME_1)
            a += multiplyHigh(a + v, PRIME_1)

            // final64(s->n.a, s->n.b);
            0UL

        }
    }



    return uLongToLittleEndian(result)
}

/*
/**
 * Return high part of 128 bit multiplication a by b
 */
inline fun mul64x64High(a: ULong, b: ULong): ULong {
/*
  const uint64_t ll = mul_32x32_64((uint32_t)a, (uint32_t)b);
  const uint64_t lh = mul_32x32_64(a >> 32, (uint32_t)b);
  const uint64_t hl = mul_32x32_64((uint32_t)a, b >> 32);
  const uint64_t hh = mul_32x32_64(a >> 32, b >> 32);

  uint64_t l;
  add64carry_last(add64carry_first(ll, lh << 32, &l), hh, lh >> 32, h);
  add64carry_last(add64carry_first(l, hl << 32, &l), *h, hl >> 32, h);
  return l;
 */

}
 */

/**
 * Returns as a {@code long} the most significant 64 bits of the 128-bit
 * product of two 64-bit factors.
 *
 * taken from https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/java/lang/Math.java
 *
 * @param x the first value
 * @param y the second value
 * @return the result
 */
fun multiplyHigh(x: ULong, y: ULong): ULong {
    // Use technique from section 8-2 of Henry S. Warren, Jr.,
    // Hacker's Delight (2nd ed.) (Addison Wesley, 2013), 173-174.
    val x1 = x shr 32
    val x2 = x and 0xFFFFFFFFUL
    val y1 = y shr 32
    val y2 = y and 0xFFFFFFFFUL
    val z2 = x2 * y2
    val t = x1 * y2 + (z2 shr 32)
    var z1 = t and 0xFFFFFFFFUL
    val z0 = t shr 32
    z1 += x2 * y1
    return x1 * y1 + z0 + (z1 shr 32)
}

inline fun rot64(v: ULong, s: Int): ULong {
    // (v >> s) | (v << (64 - s))
    return v shr s or (v shl 64 - s)
}


inline fun littleEndianToULong(bs: ByteArray, offset: Int): ULong {
    var off = offset
    val lo = (bs[off].toInt() and 0xff) or
            (bs[++off].toInt() and 0xff shl 8) or
            (bs[++off].toInt() and 0xff shl 16) or
            (bs[++off].toInt() and 0xff shl 24)

    val hi = (bs[++off].toInt() and 0xff) or
            (bs[++off].toInt() and 0xff shl 8) or
            (bs[++off].toInt() and 0xff shl 16) or
            (bs[++off].toInt() and 0xff shl 24)

    return (hi.toULong() and 0xffffffffUL) shl 32 or (lo.toULong() and 0xffffffffUL)
}

/**
 * Return ULong value of up to 8 bytes tail in ByteArray from given offset
 */
inline fun leTail64(bs: ByteArray, offset: Int, tail: Int): ULong {
    val size = tail and 7

    println("bs: $bs, offset: $offset, tail: $tail, size: $size")

    if (size == 0)
        return littleEndianToULong(bs, offset)

    var r = 0UL
    for (i in 0 until size) {
        r += ((bs[offset + i].toInt() and 0xff).toULong() shl (8 * i))
        println("i: $i, byte: ${(bs[offset + i].toInt() and 0xff).toString(16)}, r: ${r.toString(16)}")
    }

    return r
}


/*
static __maybe_unused __always_inline uint64_t final64(uint64_t a, uint64_t b) {
  uint64_t x = (a + rot64(b, 41)) * prime_0;
  uint64_t y = (rot64(a, 23) + b) * prime_6;
  return mux64(x ^ y, prime_5);
}
 */

/**
 * Convert ULong to ByteArray in little endian bytes order
 */
inline fun uLongToLittleEndian(v: ULong): ByteArray {
    val ba = ByteArray(8)

    ba[0] = (v and 0xffUL).toByte()
    ba[1] = ((v shr 8) and 0xffUL).toByte()
    ba[2] = ((v shr 16) and 0xffUL).toByte()
    ba[3] = ((v shr 24) and 0xffUL).toByte()
    ba[4] = ((v shr 32) and 0xffUL).toByte()
    ba[5] = ((v shr 40) and 0xffUL).toByte()
    ba[6] = ((v shr 48) and 0xffUL).toByte()
    ba[7] = ((v shr 56) and 0xffUL).toByte()

    return ba
}
