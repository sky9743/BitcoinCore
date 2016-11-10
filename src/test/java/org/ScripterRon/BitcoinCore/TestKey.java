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

import java.math.BigInteger;

import javax.xml.bind.DatatypeConverter;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Test EC keys
 */
public class TestKey {

    /**
     * EC key tests
     */
    @Test
    public void testKey() {
        try {
            System.out.println("Testing EC keys");
            //
            // Generate a new private/public key pair and verify that the
            // public key is compressed
            //
            ECKey key = new ECKey();
            assertTrue("Generated public key is not compressed", key.isCompressed());
            //
            // Generate a public key from a private key and verify the public key
            //
            BigInteger privKey = new BigInteger(
                    "A64C47194715C1B3C20281E5DD24B9908C7E275B6021ED76C964792908A199FE", 16);
            byte[] checkPubKey = DatatypeConverter.parseHexBinary(
                    "03F64C5060ACD5FA12590CAABBBEF87E47B6D93C92711D541B80A8FFB3BEB8EF40");
            key = new ECKey(privKey, true);
            assertArrayEquals("Public key incorrect", checkPubKey, key.getPubKey());
            //
            // Sign data and verify the signature
            //
            byte[] contents = DatatypeConverter.parseHexBinary(
                    "A64C47194715C1B3C20281E5DD24B9908C7E275B6021ED76C964792908A199FE03F64C5060ACD5FA12590CAABBBEF87E47B6D93C92711D541B80A8FFB3BEB8EF40");
            byte[] checkSig = DatatypeConverter.parseHexBinary(
                    "3044022074E77EF69E384BA8990511F30C7AB09D0B0F40BDEB681194D58AB26B5B23CFB5022049DA8B08F8FABAAA78F0256E92A0883DF57DB1EC23C979C89E5B30AF582F36F5");
            byte[] sig = key.createSignature(contents).encodeToDER();
            assertArrayEquals("Data signature incorrect", checkSig, sig);
            //
            // Verify the data signature
            //
            assertTrue("Data signature verification failed", key.verifySignature(contents, sig));
            //
            // Sign a message and verify the signature
            //
            String message = "A64C47194715C1B3C20281E5DD24B9908C7E275B6021ED76C964792908A199FE03F64C5060ACD5FA12590CAABBBEF87E47B6D93C92711D541B80A8FFB3BEB8EF40";
            String messageSig = key.signMessage(message);
            assertEquals("Message signature incorrect",
                    "IJRzciba3J8M+TOTGk2OOHBxxf1tuL4ihYhUGlemNgaZUmM+LeoY1yrSUmskqJz9Sh7+FX5opux3UOUoQu+z7W4=",
                    messageSig);
            //
            // Verify the message signature
            //
            Address addr = new Address("1Hur5JRHgRL85rvoD8gcNpSoC4DGR9E1MJ");
            assertArrayEquals("Address public key incorrect", key.getPubKeyHash(), addr.getHash());
            assertTrue("Message signature verification failed",
                    ECKey.verifyMessage(addr.toString(), message, messageSig));
            //
            // All done
            //
            System.out.println("EC key tests completed");
        } catch (Exception exc) {
            exc.printStackTrace(System.err);
            throw new RuntimeException("Exception during EC key tests", exc);
        }
    }
}
