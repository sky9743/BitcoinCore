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
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Test protocol messages
 */
public class TestMessage implements MessageListener {

    /** Message processed */
    private boolean msgProcessed;

    /** Test block */
    private Block block;

    /**
     * Test 'cmpctblock' message
     */
    @Test
    public void testCompactBlock() {
        try {
            System.out.println("Start compact block tests");
            List<SignedInput> inputs = new ArrayList<>();
            List<TransactionOutput> outputs = new ArrayList<>();
            Sha256Hash merkleRoot = new Sha256Hash("339abf46e6269217c3dcc20603fcc3cf739689e62629efa4a0cbbf724f97c67b");
            //
            // Create the EC key used to sign the transactions
            //
            BigInteger privKey = new BigInteger("A64C47194715C1B3C20281E5DD24B9908C7E275B6021ED76C964792908A199FE", 16);
            ECKey key = new ECKey(privKey, true);
            Address addr = new Address(key.getPubKeyHash());
            //
            // Create the inputs
            //
            byte[] scriptBytes = new byte[1+1+1+20+1+1];
            scriptBytes[0] = (byte)ScriptOpCodes.OP_DUP;
            scriptBytes[1] = (byte)ScriptOpCodes.OP_HASH160;
            scriptBytes[2]=  (byte)20;
            System.arraycopy(key.getPubKeyHash(), 0, scriptBytes, 3, 20);
            scriptBytes[23] = (byte)ScriptOpCodes.OP_EQUALVERIFY;
            scriptBytes[24] = (byte)ScriptOpCodes.OP_CHECKSIG;
            Sha256Hash txHash = new Sha256Hash(Utils.singleDigest(privKey.toByteArray()));
            SignedInput input0 = new SignedInput(key, new OutPoint(txHash, 0), new BigInteger("700000000"), scriptBytes);
            txHash = new Sha256Hash(Utils.singleDigest(key.getPubKey()));
            SignedInput input1 = new SignedInput(key, new OutPoint(txHash, 1), new BigInteger("200000000"), scriptBytes);
            SignedInput input2 = new SignedInput(key, new OutPoint(merkleRoot, 0), new BigInteger("100000000"), scriptBytes);
            //
            // Create the output
            //
            TransactionOutput output0 = new TransactionOutput(0, new BigInteger("999990000"), addr);
            //
            // Create the test transactions with a transaction fee of 0.0001 BTC
            //
            inputs.add(input0);
            inputs.add(input1);
            outputs.add(output0);
            Transaction tx1 = new Transaction(inputs, outputs);
            inputs.clear();
            inputs.add(input1);
            inputs.add(input0);
            Transaction tx2 = new Transaction(inputs, outputs);
            inputs.clear();
            inputs.add(input0);
            inputs.add(input2);
            Transaction tx3 = new Transaction(inputs, outputs);
            //
            // Create the coinbase transaction
            //
            inputs.clear();
            inputs.add(new SignedInput(key, new OutPoint(Sha256Hash.ZERO_HASH, -1), BigInteger.ZERO, scriptBytes));
            outputs.clear();
            outputs.add(new TransactionOutput(0, new BigInteger("1250010000"), addr));
            Transaction coinbase = new Transaction(inputs, outputs);
            //
            // Create the dummy block (a zero previous block hash indicates this is a unit test block)
            //
            Sha256Hash prevBlock = Sha256Hash.ZERO_HASH;
            SerializedBuffer inBuffer = new SerializedBuffer(512);
            inBuffer.putInt(0x20000000)
                    .putBytes(prevBlock.getBytes())
                    .putBytes(merkleRoot.getBytes())
                    .putInt((int)(new Date().getTime()/1000))
                    .putUnsignedInt(486604799L)
                    .putUnsignedInt(9L)
                    .putVarInt(4);
            coinbase.getBytes(inBuffer);
            tx1.getBytes(inBuffer);
            tx2.getBytes(inBuffer);
            tx3.getBytes(inBuffer);
            inBuffer.rewind();
            block = new Block(inBuffer, false);
            //
            // Create the compact block message
            //
            List<Integer> prefilled = new ArrayList<>(2);
            prefilled.add(0);
            prefilled.add(3);
            Message msg = CompactBlockMessage.buildCompactBlockMessage(null, block, prefilled);
            //
            // Process the compact block message
            //
            MessageProcessor.processMessage(msg, this);
            assertTrue("Compact block message not processed", msgProcessed);
            System.out.println("Compact block tests completed");
        } catch (Exception exc) {
            exc.printStackTrace(System.err);
            throw new RuntimeException("Exception during compact block tests", exc);
        }
    }

    /**
     * Message listener
     */
    @Override
    public void processCompactBlock(Message msg, BlockHeader header, long nonce, List<Long> shortIds,
                            List<CompactBlockMessage.PrefilledTransaction> prefilledTxs) {
        List<Transaction> txList = block.getTransactions();
        assertEquals("Block identifier incorrect", block.getHash(), header.getHash());
        //
        // Verify the prefilled transactions
        //
        assertEquals("Prefilled transaction count incorrect", 2, prefilledTxs.size());
        for (int i=0; i<2; i++) {
            CompactBlockMessage.PrefilledTransaction ptx = prefilledTxs.get(i);
            assertEquals("Prefilled transaction index incorrect",
                    (i==1 ? 3 : 0), ptx.getIndex());
            assertEquals("Prefilled transaction identifier incorrect",
                    txList.get(ptx.getIndex()).getHash(), ptx.getTransaction().getHash());
        }
        //
        // Build the short identifier key
        //
        byte[] headerBytes = header.getBytes();
        byte[] input = new byte[headerBytes.length + 8];
        System.arraycopy(headerBytes, 0, input, 0, headerBytes.length);
        Utils.uint64ToByteArrayLE(nonce, input, headerBytes.length);
        byte[] keyHash = Utils.singleDigest(input);
        byte[] key = Arrays.copyOfRange(keyHash, 0, 16);
        //
        // Verify the short identifiers
        //
        assertEquals("Short identifier count incorrect", 2, shortIds.size());
        for (int i=0; i<2; i++) {
            long chkId = Utils.sipHash(key, Utils.reverseBytes(txList.get(i+1).getHash().getBytes())) & 0xffffffffffffL;
            assertEquals("Short identifier " + i + " incorrect", chkId, (long)shortIds.get(i));
        }
        msgProcessed = true;
    }
}


