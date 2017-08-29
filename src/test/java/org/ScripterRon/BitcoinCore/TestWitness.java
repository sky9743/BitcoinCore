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
            //System.out.println("Tx: " + DatatypeConverter.printHexBinary(tx.getWitnessBytes()));
            //
            // Check the serialized transaction bytes
            //
            byte[] checkTxBytes = DatatypeConverter.parseHexBinary("02000000000101DB6B1B20AA0FD7B23880BE2ECBD4A98130974CF4748FB66092AC4D3CEB1A5477010000001716001479091972186C449EB1DED22B78E40D009BDF0089FEFFFFFF02B8B4EB0B000000001976A914A457B684D7F0D539A46A45BBC043F35B59D0D96388AC0008AF2F000000001976A914FD270B1EE6ABCAEA97FEA7AD0402E8BD8AD6D77C88AC02473044022008AB531B95CB4C7A9CFC9AE6344BCC171C04299E029248F32D4845A1369D707B02203796094415268FD3022A1DB880F2555613914FA88A39DEAE0F0088B85B13346F012103AD1D8E89212F0B92C74D23BB710C00662AD1470198AC48C43F7D6F93A2A2687392040000");
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
                        ScriptParser.process(txInputs.get(i), output, System.currentTimeMillis()/1000));
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
