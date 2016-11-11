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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Segregated Witness test
 *
 * Refer to BIP 143 for a description of the P2SH-P2WPKH test case
 */
public class TestWitness {

    /**
     * Segregated witness test
     */
    @Test
    public void testWitness() {
        try {
            System.out.println("Testing Segregated Witness support");
            NetParams.SUPPORTED_SERVICES = NetParams.NODE_WITNESS;
            //
            // Create the signed inputs
            //
            List<SignedInput> inputs = new ArrayList<>();
            //
            // Input sequence number: -2
            // Connected output txID: db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477 (wire format)
            // Connected output index: 1
            // Connected output value: 10.00000000 BTC
            // Connected output script: OP_HASH160 <script-hash> OP_EQUAL
            // Public key: 03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873 (wire format)
            // Private key: eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf (wire format)
            //
            byte[] scriptBytes = DatatypeConverter.parseHexBinary("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387");
            BigInteger value = new BigInteger("1000000000");
            BigInteger privKey = new BigInteger("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf", 16);
            byte[] pubKey = DatatypeConverter.parseHexBinary("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
            ECKey key = new ECKey(pubKey, privKey, true);
            Sha256Hash txId = new Sha256Hash(
                    Utils.reverseBytes(DatatypeConverter.parseHexBinary(
                            "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477")));
            OutPoint outPoint = new OutPoint(txId, 1);
            SignedInput input = new SignedInput(key, outPoint, value, scriptBytes, -2);
            inputs.add(input);
            //
            // Check P2SH address generation
            //
            byte[] scriptHash = DatatypeConverter.parseHexBinary("4733f37cf4db86fbc2efed2500b4f4e49f312023");
            Address addr = new Address(Address.AddressType.P2SH, scriptHash);
            String stringAddress = addr.toString();
            assertEquals("P2SH address version incorrect", "3", stringAddress.substring(0, 1));
            Address checkAddress = new Address(stringAddress);
            assertEquals("P2PKH address type incorrect", Address.AddressType.P2SH, checkAddress.getType());
            assertArrayEquals("P2SH address hash incorrect", addr.getHash(), checkAddress.getHash());
            //
            // Create the outputs
            //
            List<TransactionOutput> outputs = new ArrayList<>();
            //
            // Output value: 1.99996600 BTC
            // Output script: OP_DUP OP_HASH160 <pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
            //
            value = new BigInteger("0bebb4b8", 16);
            scriptBytes = DatatypeConverter.parseHexBinary("76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac");
            TransactionOutput output = new TransactionOutput(0, value, scriptBytes);
            outputs.add(output);
            //
            // Output value: 8.00000000 BTC
            // Output script: OP_DUP OP_HASH160 <pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
            //
            value = new BigInteger("2faf0800", 16);
            scriptBytes = DatatypeConverter.parseHexBinary("76a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac");
            output = new TransactionOutput(1, value, scriptBytes);
            outputs.add(output);
            //
            // Create the segregated witness transaction
            //
            long lockTime = 0x492;
            Transaction tx = new Transaction(inputs, outputs, lockTime);
            //
            // Check the serialized transaction bytes
            //
            byte[] checkTxBytes = DatatypeConverter.parseHexBinary("01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000");
            assertArrayEquals("New transaction: Serialized bytes incorrect", checkTxBytes, tx.getWitnessBytes());
            //
            // Create a new transaction using the serialized bytes
            //
            SerializedBuffer outBuffer = new SerializedBuffer(1024);
            tx.getWitnessBytes(outBuffer);
            outBuffer.rewind();
            Transaction checkTx = new Transaction(outBuffer);
            //
            // Check the serialized transaction bytes
            //
            assertArrayEquals("Payload transaction: Serialized bytes incorrect", checkTxBytes, checkTx.getWitnessBytes());
            //
            // Validate the transaction signature
            //
            List<TransactionInput> txInputs = tx.getInputs();
            assertEquals("Incorrect number of inputs", inputs.size(), txInputs.size());
            for (int i=0; i<txInputs.size(); i++) {
                input = inputs.get(i);
                outPoint = input.getOutPoint();
                output = new TransactionOutput(outPoint.getIndex(), input.getValue(), input.getScriptBytes());
                assertTrue("Transaction signature validation failed",
                        ScriptParser.process(txInputs.get(i), output, new Date().getTime()/1000));
            }
            //
            // All done
            //
            System.out.println("Segregated Witness tests completed");
        } catch (Exception exc) {
            exc.printStackTrace(System.err);
            throw new RuntimeException("Exception during Segregated Witness test", exc);
        }
    }
}
