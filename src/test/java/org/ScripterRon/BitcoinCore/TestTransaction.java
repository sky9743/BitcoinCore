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
 * Transaction tests
 */
public class TestTransaction {

    /**
     * Transaction tests
     */
    @Test
    public void testTransaction() {
        try {
            System.out.println("Testing transaction support");
            //
            // Create the EC key
            //
            BigInteger privKey = new BigInteger("A64C47194715C1B3C20281E5DD24B9908C7E275B6021ED76C964792908A199FE", 16);
            ECKey key = new ECKey(privKey, true);
            Address addr = new Address(key.getPubKeyHash());
            //
            // Create the signed inputs
            //
            List<SignedInput> inputs = new ArrayList<>();
            byte[] scriptBytes = new byte[1+1+1+20+1+1];
            scriptBytes[0] = (byte)ScriptOpCodes.OP_DUP;
            scriptBytes[1] = (byte)ScriptOpCodes.OP_HASH160;
            scriptBytes[2]=  (byte)20;
            System.arraycopy(key.getPubKeyHash(), 0, scriptBytes, 3, 20);
            scriptBytes[23] = (byte)ScriptOpCodes.OP_EQUALVERIFY;
            scriptBytes[24] = (byte)ScriptOpCodes.OP_CHECKSIG;
            Sha256Hash txHash = new Sha256Hash(Utils.singleDigest(privKey.toByteArray()));
            inputs.add(new SignedInput(key, new OutPoint(txHash, 0), new BigInteger("800000000"), scriptBytes));
            txHash = new Sha256Hash(Utils.singleDigest(key.getPubKey()));
            inputs.add(new SignedInput(key, new OutPoint(txHash, 1), new BigInteger("200000000"), scriptBytes));
            //
            // Check P2PKH address generation
            //
            String stringAddress = addr.toString();
            assertEquals("P2PKH address version incorrect", "1", stringAddress.substring(0, 1));
            Address checkAddress = new Address(stringAddress);
            assertEquals("P2PKH address type incorrect", Address.AddressType.P2PKH, checkAddress.getType());
            assertArrayEquals("P2PKH address hash incorrect", addr.getHash(), checkAddress.getHash());
            //
            // Create the output
            //
            List<TransactionOutput> outputs = new ArrayList<>();
            outputs.add(new TransactionOutput(0, new BigInteger("999990000"), addr));
            //
            // Create the transaction and verify the serialized bytes
            //
            Transaction tx = new Transaction(inputs, outputs);
            byte[] checkTxBytes = DatatypeConverter.parseHexBinary(
                "0100000002220C369F44DFDB3C5D2DCEE7343EDB56094865832AB57D989F7AE524D4414188000000006A473044022067B85ABE1E9C193E730676561E33CF1628501D55C891D1360F496F20E79D63BA02207A1B47E0E466DF6D9D2C35F34349EC06CBEF468CA048FDF733E9506F55BC78F0012103F64C5060ACD5FA12590CAABBBEF87E47B6D93C92711D541B80A8FFB3BEB8EF40FFFFFFFFBB475042DF23EF79FBF22C4EFC44563BF1912796B57419968E9846AF2CE5E4C1010000006A473044022014F44751E7173A721A849739D01DD8CE6C3E907DC6AAB35B0BE45D2ADF3107FD022059962F9148BF145E4A2C806A374A0BAD0D79ACD1BEDA134446389A758A221003012103F64C5060ACD5FA12590CAABBBEF87E47B6D93C92711D541B80A8FFB3BEB8EF40FFFFFFFF01F0A29A3B000000001976A914B9809B8AB9213333514B5457B6256C5F0D46264988AC00000000");
            assertArrayEquals("Serialized transaction incorrect", checkTxBytes, tx.getBytes());
            //
            // Validate the transaction signature
            //
            List<TransactionInput> txInputs = tx.getInputs();
            assertEquals("Incorrect number of inputs", inputs.size(), txInputs.size());
            for (int i=0; i<txInputs.size(); i++) {
                SignedInput input = inputs.get(i);
                OutPoint outPoint = input.getOutPoint();
                TransactionOutput output = new TransactionOutput(outPoint.getIndex(), input.getValue(), input.getScriptBytes());
                assertTrue("Transaction signature validation failed",
                        ScriptParser.process(txInputs.get(i), output, System.currentTimeMillis()/1000));
            }
            //
            // All done
            //
            System.out.println("Transaction tests completed");
        } catch (Exception exc) {
            exc.printStackTrace(System.err);
            throw new RuntimeException("Exception during transaction tests");
        }
    }
}
