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
 * The 'blocktxn' message contains a list of transactions as defined by BIP 152.
 * Compact block support is activated for protocol versions >= 70014 and is
 * enabled upon receipt of one or more 'sendcmpct' messages from a peer.
 *
 * <p>Reject Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   32 bytes   BlockHash       Block hash
 *   VarInt     TxCount         Number of transactions
 *   Variable   Transactions    Transactions
 * </pre>
 */
public class BlockTransactionsMessage {

    /**
     * Build a 'blocktxn' message
     *
     * @param       peer            Destination peer
     * @param       blockHash       Block identifier
     * @param       txList          Transactions
     * @return                      'blocktxn' message
     */
    public static Message buildBlockTransactionsMessage(Peer peer, Sha256Hash blockHash, List<Transaction> txList) {
        if (txList.isEmpty())
            throw new IllegalArgumentException("Transaction list is empty");
        //
        // Build the message data
        //
        SerializedBuffer msgBuffer = new SerializedBuffer();
        msgBuffer.putBytes(Utils.reverseBytes(blockHash.getBytes()))
                 .putVarInt(txList.size());
        txList.forEach((tx) -> tx.getBytes(msgBuffer));
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("blocktxn", msgBuffer);
        return new Message(buffer, peer, MessageHeader.MessageCommand.BLOCKTXN);
    }

    /**
     * Process a 'blocktxn' message
     *
     * @param       msg                     Message
     * @param       inBuffer                Input buffer
     * @param       msgListener             Message listener
     * @throws      EOFException            Serialized byte stream is too short
     * @throws      VerificationException   Message verification failure
     */
    public static void processBlockTransactionsMessage(
                                    Message msg, SerializedBuffer inBuffer, MessageListener msgListener)
                                    throws EOFException, VerificationException {
        //
        // Get the block identifer and the transaction count
        //
        Sha256Hash blockHash = new Sha256Hash(Utils.reverseBytes(inBuffer.getBytes(32)));
        int count = inBuffer.getVarInt();
        //
        // Get the transactions
        //
        List<Transaction> txList = new ArrayList<>(count);
        for (int i=0; i<count; i++) {
            txList.add(new Transaction(inBuffer));
        }
        //
        // Notify the message listener
        //
        msgListener.processBlockTransactions(msg, blockHash, txList);
    }
}
