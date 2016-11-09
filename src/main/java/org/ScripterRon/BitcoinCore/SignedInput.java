/**
 * Copyright 2013-2016 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.BitcoinCore;

import java.math.BigInteger;

/**
 * SignedInput represents a transaction output that is being spent as part of
 * a new transaction.  It contains the key needed to sign the transaction as
 * well as the transaction output hash and index.
 */
public class SignedInput {

    /** Connected transaction output */
    private final OutPoint outPoint;

    /** Transaction output value */
    private final BigInteger value;

    /** Transaction output script */
    private final byte[] scriptBytes;

    /** Key associated with the transaction output */
    private final ECKey key;

    /** Transaction input sequence number */
    private final int seqNumber;

    /**
     * Creates a new SignedInput
     *
     * @param       key                 Key to sign the transaction
     * @param       outPoint            Connected transaction output
     * @param       value               Transaction output value
     * @param       scriptBytes         Transaction output script bytes
     */
    public SignedInput(ECKey key, OutPoint outPoint, BigInteger value, byte[] scriptBytes) {
        this(key, outPoint, value, scriptBytes, -1);
    }

    /**
     * Creates a new SignedInput
     *
     * @param       key                 Key to sign the transaction
     * @param       outPoint            Connected transaction output
     * @param       value               Transaction output value
     * @param       scriptBytes         Transaction output script bytes
     * @param       seqNumber           Transaction input sequence number
     */
    public SignedInput(ECKey key, OutPoint outPoint, BigInteger value, byte[] scriptBytes, int seqNumber) {
        this.key = key;
        this.outPoint = outPoint;
        this.value = value;
        this.scriptBytes = scriptBytes;
        this.seqNumber = seqNumber;
    }

    /**
     * Returns the key
     *
     * @return                          Key to sign the transaction
     */
    public ECKey getKey() {
        return key;
    }

    /**
     * Returns the connected transaction outpoint
     *
     * @return                          Transaction outpoint
     */
    public OutPoint getOutPoint() {
        return outPoint;
    }

    /**
     * Returns the transaction output value
     *
     * @return                          Transaction output value
     */
    public BigInteger getValue() {
        return value;
    }

    /**
     * Returns the transaction output script
     *
     * @return                          Transaction output script
     */
    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    /**
     * Return the input sequence number
     *
     * @return                          Transaction input sequence number
     */
    public int getSeqNumber() {
        return seqNumber;
    }
}
