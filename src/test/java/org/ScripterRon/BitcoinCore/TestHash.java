/*
 * Copyright 2016 Ronald W Hoffman.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.BitcoinCore;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * Hash tests
 */
public class TestHash {

    /**
     * SipHash tests
     */
    @Test
    public void testSipHash() {
        try {
            System.out.println("Testing SipHash");
            byte[] key = javax.xml.bind.DatatypeConverter.parseHexBinary(
                    "000102030405060708090a0b0c0d0e0f");
            byte[] input = javax.xml.bind.DatatypeConverter.parseHexBinary(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
            long result = Utils.sipHash(key, null);
            assertEquals("SipHash incorrect for empty input", 0x726fdb47dd0e0e31L, result);
            result = Utils.sipHash(key, Arrays.copyOfRange(input, 0, 1));
            assertEquals("SipHash incorrect for 1-byte input", 0x74f839c593dc67fdL, result);
            result = Utils.sipHash(key, Arrays.copyOfRange(input, 0, 8));
            assertEquals("SipHash incorrect for 8-byte input", 0x93f5f5799a932462L, result);
            result = Utils.sipHash(key, Arrays.copyOfRange(input, 0, 16));
            assertEquals("SipHash incorrect for 16-byte input", 0x3f2acc7f57c29bdbL, result);
            result = Utils.sipHash(key, Arrays.copyOfRange(input, 0, 27));
            assertEquals("SipHash incorrect for 27-byte input", 0x2f2e6163076bcfadL, result);
            result = Utils.sipHash(key, Arrays.copyOfRange(input, 0, 32));
            assertEquals("SipHash incorrect for 32-byte input", 0x7127512f72f27cceL, result);
            result = Utils.sipHash(key, Arrays.copyOfRange(input, 0, 40));
            assertEquals("SipHash incorrect for 40-byte input", 0x0e3ea96b5304a7d0L, result);
            result = Utils.sipHash(key, input);
            assertEquals("SipHash incorrect for 48-byte input", 0xe612a3cb9ecba951L, result);
            System.out.println("SipHash tests completed");
        } catch (Exception exc) {
            exc.printStackTrace(System.err);
            throw new RuntimeException("Exception during SipHash tests", exc);
        }
    }
}
