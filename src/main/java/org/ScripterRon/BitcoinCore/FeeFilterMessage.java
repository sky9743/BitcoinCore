/*
 * Copyright 2017 Ronald W Hoffman
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

/**
 * <p>The 'feefilter' message is sent by a remote peer to advertise the minimum transaction fee
 * accepted by the peer.  This is an unsolicited message and is sent during the initial connection
 * handshake.</p>
 *
 * <p>Fee Filter Message:</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   Long       Fee                 Minimum fee (satoshis/byte)
 * </pre>
 */
public class FeeFilterMessage {

    /**
     * Build a 'feefilter' message
     *
     * @param       peer            Destination peer
     * @param       fee             Minimum fee (satoshis/byte)
     * @return                      'feefilter' message
     */
    public static Message buildFeeFilterMessage(Peer peer, long fee) {
        //
        // Build the message data
        //
        SerializedBuffer msgBuffer = new SerializedBuffer(8);
        msgBuffer.putLong(fee);
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("feefilter", msgBuffer);
        return new Message(buffer, peer, MessageHeader.MessageCommand.FEEFILTER);
    }

    /**
     * Process an 'inv' message.
     *
     * @param       msg                     Message
     * @param       inBuffer                Input buffer
     * @param       msgListener             Message listener
     * @throws      EOFException            End-of-data while processing input stream
     * @throws      VerificationException   Verification failed
     */
    public static void processFeeFilterMessage(Message msg, SerializedBuffer inBuffer, MessageListener msgListener)
                                            throws EOFException, VerificationException {
        //
        // Get the minum fee
        //
        long fee = inBuffer.getLong();
        //
        // Notify the message listener
        //
        msgListener.processFeeFilter(msg, fee);
    }
}
