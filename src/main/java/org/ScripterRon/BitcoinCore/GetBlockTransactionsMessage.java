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
import java.util.List;

/**
 * The 'getblocktxn' message contains a list of transaction indexes as defined by BIP 152.
 * Compact block support is activated for protocol versions >= 70014 and is
 * enabled upon receipt of one or more 'sendcmpct' messages from a peer.
 *
 * <p>Reject Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   32 bytes   BlockHash       Block hash
 *   VarInt     IndexCount      Number of transaction indexes
 *   Variable   Indexes         Differential transaction indexes
 * </pre>
 *
 * <p>A differential transaction index is added to the next expected index
 * to get the actual transaction index.  For example, if all block transactions
 * are present in the list, each differential index would be 0.  If the second
 * and third transactions are omitted from the list, then the second transaction
 * in the list would have a differential index of 2.</p>
 */
public class GetBlockTransactionsMessage {

    /**
     * Build a 'getblocktxn' message
     *
     * @param       peer            Destination peer
     * @param       blockHash       Block identifier
     * @param       indexes         List of transaction indexes in ascending order
     * @return                      'getblocktxn' message
     */
    public static Message buildGetBlockTransactionsMessage(Peer peer, Sha256Hash blockHash, List<Integer> indexes) {
        if (indexes.isEmpty())
            throw new IllegalArgumentException("Transaction index list is empty");
        //
        // Build the message data
        //
        SerializedBuffer msgBuffer = new SerializedBuffer();
        msgBuffer.putBytes(Utils.reverseBytes(blockHash.getBytes()))
                 .putVarInt(indexes.size());
        int nextIndex = 0;
        for (Integer index : indexes) {
            msgBuffer.putVarInt(index - nextIndex);
            nextIndex = index + 1;
        }
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("getblocktxn", msgBuffer);
        return new Message(buffer, peer, MessageHeader.MessageCommand.GETBLOCKTXN);
    }

    /**
     * Process a 'getblocktxn' message
     *
     * @param       msg                     Message
     * @param       inBuffer                Input buffer
     * @param       msgListener             Message listener
     * @throws      EOFException            Serialized byte stream is too short
     * @throws      VerificationException   Message verification failure
     */
    public static void processGetBlockTransactionsMessage(
                                    Message msg, SerializedBuffer inBuffer, MessageListener msgListener)
                                    throws EOFException, VerificationException {
        //
        // Get the block identifer and the index count
        //
        Sha256Hash blockHash = new Sha256Hash(Utils.reverseBytes(inBuffer.getBytes(32)));
        int count = inBuffer.getVarInt();
        //
        // Get the transaction indexes
        //
        List<Integer> indexes = new ArrayList<>(count);
        int nextIndex = 0;
        for (int i=0; i<count; i++) {
            int index = inBuffer.getVarInt() + nextIndex;
            indexes.add(index);
            nextIndex = index + 1;
        }
        //
        // Notify the message listener
        //
        msgListener.processGetBlockTransactions(msg, blockHash, indexes);
    }
}
