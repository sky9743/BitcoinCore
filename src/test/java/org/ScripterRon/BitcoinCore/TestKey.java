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
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
    public void testECKey() {
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

    /**
     * HD key tests
     */
    @Test
    public void testHDKey() {
        try {
            System.out.println("Testing HD keys");
            byte[] seed = DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f");
            //
            // Create the root key (m)
            //
            HDKey rootKey = HDKeyDerivation.createRootKey(seed);
            assertEquals("Root key depth is not zero", 0, rootKey.getDepth());
            assertEquals("Root key fingerprint incorrect", 876747070, rootKey.getFingerprint());
            assertEquals("Root private key incorrect",
                    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                    rootKey.serializePrivKeyToString());
            assertEquals("Root public key incorrect",
                    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                    rootKey.serializePubKeyToString());
            //
            // Create the hardened account key (m/0h)
            //
            HDKey accountKey = HDKeyDerivation.deriveChildKey(rootKey, 0, true);
            assertEquals("Account key depth is not 1", 1, accountKey.getDepth());
            assertEquals("Account public key incorrect",
                    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                    accountKey.serializePubKeyToString());
            assertEquals("Account private key incorrect",
                    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                    accountKey.serializePrivKeyToString());
            assertTrue("Account key is not hardened", accountKey.isHardened());
            //
            // Create the chain key (m/0h/1)
            //
            HDKey chainKey = HDKeyDerivation.deriveChildKey(accountKey, 1, false);
            assertEquals("Chain key fingerprint is not correct", -1091198215, chainKey.getFingerprint());
            assertEquals("Chain key depth is not 2", 2, chainKey.getDepth());
            assertEquals("Chain public key incorrect",
                    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                    chainKey.serializePubKeyToString());
            assertEquals("Chain private key incorrect",
                    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                    chainKey.serializePrivKeyToString());
            assertFalse("Chain key is hardened", chainKey.isHardened());
            //
            // Create application key (m/0h/1/2h)
            //
            HDKey key = HDKeyDerivation.deriveChildKey(chainKey, 2, true);
            assertEquals("Public key m/0h/1/2h incorrect",
                    "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                    key.serializePubKeyToString());
            assertEquals("Private key m/0h/1/2h incorrect",
                    "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                    key.serializePrivKeyToString());
            assertTrue("Key m/0h/1/2h is not hardened", key.isHardened());
            //
            // Create application key (m/0h/1/2h/2)
            //
            key = HDKeyDerivation.deriveChildKey(key, 2, false);
            assertEquals("Public key m/0h/1/2h/2 incorrect",
                    "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                    key.serializePubKeyToString());
            assertEquals("Private key m/0h/1/2h/2 incorrect",
                    "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                    key.serializePrivKeyToString());
            assertFalse("Key m/0h/1/2h/2 is hardened", key.isHardened());
            //
            // Create application key (m/0h/1/2h/2/1000000000
            //
            key = HDKeyDerivation.deriveChildKey(key, 1000000000, false);
            assertEquals("Public key m/0h/1/2h/2/1000000000 incorrect",
                    "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                    key.serializePubKeyToString());
            assertEquals("Private key m/0h/1/2h/2/1000000000 incorrect",
                    "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                    key.serializePrivKeyToString());
            assertFalse("Key m/0h/1/2h/2/1000000000 is hardened", key.isHardened());
            //
            // Check the key path
            //
            List<Integer> path = key.getPath();
            assertEquals("Key path length incorrect", 5, path.size());
            assertEquals("Path 0 incorrect", 0, (int)path.get(0));
            assertEquals("Path 1 incorrect", 1, (int)path.get(1));
            assertEquals("Path 2 incorrect", 2, (int)path.get(2));
            assertEquals("Path 3 incorrect", 2, (int)path.get(3));
            assertEquals("Path 4 incorrect", 1000000000, (int)path.get(4));
            assertEquals("String path incorrect", "m/0/1/2/2/1000000000", key.toString());
            //
            // Check private key deserialization
            //
            String serString = key.serializePrivKeyToString();
            key = HDKey.deserializeStringToKey(serString, key.getParent());
            assertEquals("Deserialized private key incorrect",
                    serString, key.serializePrivKeyToString());
            //
            // Create a public-key only chain (m/0h/1p)
            //
            HDKey chainPubKey = new HDKey(chainKey.getPubKey(), chainKey.getChainCode(), chainKey.getParent(), 1, false);
            assertEquals("Public key m/0h/1p incorrect",
                    chainKey.serializePubKeyToString(), chainPubKey.serializePubKeyToString());
            //
            // Create application key (m/0h/1p/0)
            //
            key = HDKeyDerivation.deriveChildKey(chainPubKey, 0, false);
            assertEquals("Public key m/0h/1p/0 incorrect",
                    "xpub6D4BDPcEgbv6qt4SWJPmbJ6aMV65EvtXTh9ZQkFhypze4kG5NYtpV9WeJroBCJXojh4PRfPV9KTyh7vDNCxGupcyJkc8WcJoSdj5b2gwsNv",
                    key.serializePubKeyToString());
            //
            // Check public key deserialization
            //
            serString = key.serializePubKeyToString();
            key = HDKey.deserializeStringToKey(serString, key.getParent());
            assertEquals("Deserialized public key incorrect",
                    serString, key.serializePubKeyToString());
            //
            // All done
            //
            System.out.println("HD key tests completed");
        } catch (Exception exc) {
            exc.printStackTrace(System.err);
            throw new RuntimeException("Exception during HD key tests", exc);
        }
    }
}
