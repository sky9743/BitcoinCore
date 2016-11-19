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
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Hierarchical Deterministic key derivation (BIP 32)
 */
public class HDKeyDerivation {

    /**
     * Generate a root key from the given seed.  The seed must be at least 128 bits.
     *
     * @param   seed                    HD seed
     * @return                          Root key
     * @throws  HDDerivationException   Generated master key is invalid
     */
    public static HDKey createRootKey(byte[] seed) throws HDDerivationException {
        if (seed.length < 16)
            throw new IllegalArgumentException("Seed must be at least 128 bits");
        //
        // From BIP 32:
        // - Generate a seed byte sequence S of a chosen length (between 128 and 512 bits)
        // - Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
        // - Split I into two 32-byte sequences, IL and IR.
        // - Use parse256(IL) as master secret key, and IR as master chain code.
        //   In case IL is 0 or ≥n, the master key is invalid.
        //
        byte[] i = Utils.hmacSha512("Bitcoin seed".getBytes(), seed);
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] ir = Arrays.copyOfRange(i, 32, 64);
        BigInteger privKey = new BigInteger(1, il);
        if (privKey.signum() == 0)
            throw new HDDerivationException("Generated master private key is zero");
        if (privKey.compareTo(ECKey.ecParams.getN()) >= 0)
            throw new HDDerivationException("Generated master private key is not less than N");
        return new HDKey(privKey, ir, null, 0, false);
    }

    /**
     * Derive a child key from the specified parent.  The parent must have a private key.
     *
     * @param   parent                  Parent key
     * @param   childNumber             Child number
     * @param   hardened                TRUE to create a hardened key
     * @return                          Derived key
     * @throws  HDDerivationException   Unable to derive key
     */
    public static HDKey deriveChildKey(HDKey parent, int childNumber, boolean hardened)
                                        throws HDDerivationException {
        if ((childNumber&HDKey.HARDENED_FLAG) != 0)
            throw new IllegalArgumentException("Hardened flag must not be set in child number");
        BigInteger parentPrivKey = parent.getPrivKey();
        if (parentPrivKey == null)
            throw new IllegalArgumentException("Parent does not have a private key");
        byte[] parentPubKey = parent.getPubKey();
        if (parentPubKey.length != 33)
            throw new IllegalStateException("Parent public key is not 33 bytes");
        //
        // From BIP 32:
        // - Check whether i ≥ 231 (whether the child is a hardened key).
        // - If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
        //   (Note: The 0x00 pads the private key to make it 33 bytes long.)
        // - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
        // - Split I into two 32-byte sequences, IL and IR.
        // - The returned child key ki is parse256(IL) + kpar (mod n).
        // - The returned chain code ci is IR.
        //
        // In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid
        //
        ByteBuffer dataBuffer = ByteBuffer.allocate(37);
        if (hardened) {
            dataBuffer.put(parent.getPaddedPrivKeyBytes())
                      .putInt(childNumber|HDKey.HARDENED_FLAG);
        } else {
            dataBuffer.put(parentPubKey)
                      .putInt(childNumber);
        }
        byte[] i = Utils.hmacSha512(parent.getChainCode(), dataBuffer.array());
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] ir = Arrays.copyOfRange(i, 32, 64);
        BigInteger ilInt = new BigInteger(1, il);
        if (ilInt.compareTo(ECKey.ecParams.getN()) >= 0)
            throw new HDDerivationException("Derived private key is not less than N");
        BigInteger ki = parentPrivKey.add(ilInt).mod(ECKey.ecParams.getN());
        if (ki.signum() == 0)
            throw new HDDerivationException("Derived private key is zero");
        return new HDKey(ki, ir, parent, childNumber, hardened);
    }
}
