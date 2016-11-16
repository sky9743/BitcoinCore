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
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Test script processing
 */
public class TestScript {

    /**
     * Test OP_CHECKLOCKTIMEVERIFY
     */
    @Test
    public void testCLTV() {
        try {
            System.out.println("Start OP_CHECKLOCKTIMEVERIFY tests");
            //
            // Create a test transaction with a lock time of 400000
            //
            Transaction tx = createTransaction();
            TransactionInput input = tx.getInputs().get(0);
            long blockTime = new Date().getTime()/1000;
            //
            // Test failure: Required lock time 500000, Transaction lock time 400000
            //
            // Input script: <TRUE>
            // Output script: <500000> OP_CHECKLOCKTIMEVERIFY OP_DROP
            //
            byte[] inScriptBytes = new byte[2];
            inScriptBytes[0] = (byte)1;
            inScriptBytes[1] = (byte)1;
            input.setScriptBytes(inScriptBytes);
            byte[] outScriptBytes = new byte[6];
            outScriptBytes[0] = (byte)3;
            outScriptBytes[1] = (byte)0x20;
            outScriptBytes[2] = (byte)0xa1;
            outScriptBytes[3] = (byte)0x07;
            outScriptBytes[4] = (byte)ScriptOpCodes.OP_CHECKLOCKTIMEVERIFY;
            outScriptBytes[5] = (byte)ScriptOpCodes.OP_DROP;
            TransactionOutput output = new TransactionOutput(0, BigInteger.ZERO, outScriptBytes);
            boolean txValid = ScriptParser.process(input, output, blockTime);
            assertFalse("OP_CHECKLOCKTIMEVERIFY did not fail", txValid);
            //
            // Test success: Required lock time 300000, Transaction lock time 400000
            //
            outScriptBytes[1] = (byte)0xe0;
            outScriptBytes[2] = (byte)0x93;
            outScriptBytes[3] = (byte)0x04;
            txValid = ScriptParser.process(input, output, blockTime);
            assertTrue("OP_CHECKLOCKTIMEVERIFY did not succeed", txValid);
            System.out.println("OP_CHECKLOCKTIMEVERIFY tests completed");
        } catch (Exception exc) {
            exc.printStackTrace(System.err);
            throw new RuntimeException("Exception during OP_CHECKLOCKTIMEVERIFY tests", exc);
        }
    }

    /**
     * Create the test transaction
     *
     * @return                          Transaction
     * @throws  ECException             EC key exception
     * @throws  ScriptException         Script exception
     * @throws  VerificationException   Transaction verification exception
     */
    private Transaction createTransaction() throws ECException, ScriptException, VerificationException {
        //
        // Create the EC key used to sign the transactions
        //
        BigInteger privKey = new BigInteger("A64C47194715C1B3C20281E5DD24B9908C7E275B6021ED76C964792908A199FE", 16);
        ECKey key = new ECKey(privKey, true);
        Address addr = new Address(key.getPubKeyHash());
        //
        // Create the transaction
        //
        List<SignedInput> inputs = new ArrayList<>();
        SignedInput input = new SignedInput(key, new OutPoint(Sha256Hash.ZERO_HASH, 0),
                new BigInteger("1000000000"), Script.getScriptPubKey(addr, false), 100);
        inputs.add(input);
        List<TransactionOutput> outputs = new ArrayList<>();
        TransactionOutput output = new TransactionOutput(0, new BigInteger("999990000"), addr);
        outputs.add(output);
        Transaction tx = new Transaction(inputs, outputs, 400000);
        return tx;
    }
}
