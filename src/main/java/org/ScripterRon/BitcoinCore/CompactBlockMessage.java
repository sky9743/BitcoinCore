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

import java.io.EOFException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * The 'cmpctblock' message contains a compact block as defined by BIP 152.
 * Compact block support is activated for protocol versions >= 70014 and is
 * enabled upon receipt of one or more 'sendcmpct' messages from a peer.
 *
 * <p>Reject Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   80 bytes   Header          The block header
 *   8          Nonce           Calculated from the transaction identifiers
 *   VarInt     ShortIdCount    Number of short identifiers
 *   Variable   ShortIds        List of 6-byte short identifiers
 *   VarInt     PrefilledCount  Number of prefilled transactions
 *   Variable   PrefilledTxs    List of prefilled transactions
 * </pre>
 *
 * <p>Prefilled transaction</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   VarInt     Index           Differential transaction index
 *   Variable   Tx              Transaction
 * </pre>
 */
public class CompactBlockMessage {

    /** Random number generator */
    private static final Random random = new Random();

    /**
     * Build a 'cmpctblock' message
     *
     * @param       peer            Destination peer
     * @param       block           Block
     * @param       prefilled       List of prefilled transaction indexes
     * @return                      'cmpctblock' message
     */
    public static Message buildCompactBlockMessage(Peer peer, Block block, List<Integer> prefilled) {
        long nonce = random.nextLong();
        byte[] headerBytes = block.getHeaderBytes();
        //
        // Build the list of prefilled transactions
        //
        // We always send the coinbase transaction
        //
        List<Integer> sortedIndexes = new ArrayList<>(prefilled);
        Collections.sort(sortedIndexes);
        if (sortedIndexes.isEmpty() || sortedIndexes.get(0) != 0)
            sortedIndexes.add(0, 0);
        List<Transaction> txs = block.getTransactions();
        List<PrefilledTransaction> prefilledTxs = new ArrayList<>();
        for (Integer index : prefilled) {
            if (index >= txs.size())
                throw new IllegalArgumentException("Prefilled transaction index " + index + " is not valid");
            prefilledTxs.add(new PrefilledTransaction(index, txs.get(index)));
        }
        //
        // Calcule the SipHash key
        //
        // 1) Single-SHA256 of the header bytes and the little-endian nonce
        // 2) Key0 consists of the first 8 bytes of the hash in little-endian format
        // 3) Key1 consists of the second 8 bytes of the hash in little-endian format
        //
        byte[] input = new byte[headerBytes.length + 8];
        System.arraycopy(headerBytes, 0, input, 0, headerBytes.length);
        Utils.uint64ToByteArrayLE(nonce, input, headerBytes.length);
        byte[] keyHash = Utils.singleDigest(input);
        byte[] key = Arrays.copyOfRange(keyHash, 0, 16);
        //
        // Calculate the short transaction identifiers
        //
        List<Sha256Hash> shortTxs = new ArrayList<>(txs.size());
        txs.forEach((tx) -> shortTxs.add(tx.getHash()));
        prefilledTxs.forEach((tx) -> shortTxs.remove(tx.getTransaction().getHash()));
        List<byte[]> shortIds = new ArrayList<>(prefilledTxs.size());
        shortTxs.forEach((id) -> {
            long shortId = Utils.sipHash(key, Utils.reverseBytes(id.getBytes()));
            byte[] idBytes = new byte[6];
            idBytes[0] = (byte)shortId;
            idBytes[1] = (byte)(shortId>>8);
            idBytes[2] = (byte)(shortId>>16);
            idBytes[3] = (byte)(shortId>>24);
            idBytes[4] = (byte)(shortId>>32);
            idBytes[5] = (byte)(shortId>>40);
            shortIds.add(idBytes);
        });
        //
        // Build the message data
        //
        SerializedBuffer msgBuffer = new SerializedBuffer();
        msgBuffer.putBytes(headerBytes)
                 .putLong(nonce)
                 .putVarInt(shortIds.size());
        shortIds.forEach((id) -> msgBuffer.putBytes(id));
        msgBuffer.putVarInt(prefilledTxs.size());
        int nextIndex = 0;
        for (PrefilledTransaction tx : prefilledTxs) {
            msgBuffer.putVarInt(tx.getIndex() - nextIndex);
            tx.getTransaction().getBytes(msgBuffer);
            nextIndex = tx.getIndex() + 1;
        }
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("cmpctblock", msgBuffer);
        return new Message(buffer, peer, MessageHeader.MessageCommand.CMPCTBLOCK);
    }

    /**
     * Process a 'cmpctblock' message
     *
     * @param       msg                     Message
     * @param       inBuffer                Input buffer
     * @param       msgListener             Message listener
     * @throws      EOFException            Serialized byte stream is too short
     * @throws      VerificationException   Message verification failure
     */
    public static void processCompactBlockMessage(Message msg, SerializedBuffer inBuffer, MessageListener msgListener)
                                    throws EOFException, VerificationException {
        //
        // Get the block header and the transaction nonce
        //
        BlockHeader header = new BlockHeader(inBuffer, true);
        long nonce = inBuffer.getLong();
        //
        // Get the short transaction identifiers
        //
        int count = inBuffer.getVarInt();
        List<Long> shortIds = new ArrayList<>(count);
        for (int i=0; i<count; i++) {
            byte[] idBytes = inBuffer.getBytes(6);
            long id = ((long)idBytes[0]&255) | (((long)idBytes[1]&255) << 8) |
                    (((long)idBytes[2]&255) << 16) | (((long)idBytes[3]&255) << 24) |
                    (((long)idBytes[4]&255) << 32) | (((long)idBytes[5]&255) <<40);
            shortIds.add(id);
        }
        //
        // Get the prefilled transactions
        //
        count = inBuffer.getVarInt();
        List<PrefilledTransaction> prefilledTxs = new ArrayList<>(count);
        int nextIndex = 0;
        for (int i=0; i<count; i++) {
            int diff = inBuffer.getVarInt();
            Transaction tx = new Transaction(inBuffer);
            prefilledTxs.add(new PrefilledTransaction(nextIndex + diff, tx));
            nextIndex += diff + 1;
        }
        //
        // Notify the message listener
        //
        msgListener.processCompactBlock(msg, header, nonce, shortIds, prefilledTxs);
    }

    /**
     * Prefilled transaction
     */
    public static class PrefilledTransaction {

        /** Index within block */
        private final int index;

        /** Transaction */
        private final Transaction tx;

        /**
         * Create a prefilled transaction
         *
         * @param   index           Index within block
         * @param   tx              Transaction
         */
        public PrefilledTransaction(int index, Transaction tx) {
            this.index = index;
            this.tx = tx;
        }

        /**
         * Return the transaction index
         *
         * @return                  Index within block
         */
        public int getIndex() {
            return index;
        }

        /**
         * Return the transaction
         *
         * @return                  Transaction
         */
        public Transaction getTransaction() {
            return tx;
        }
    }
}
