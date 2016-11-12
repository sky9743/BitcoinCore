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

import java.nio.ByteBuffer;

/**
 * The 'sendheaders' message notifies the peer that a block header message can be
 * sent instead of an inventory message when announcing a new block.  This improves
 * the headers-first download protocol implemented in Bitcoin Core 0.10.
 *
 * The 'sendheaders' message is defined in BIP 130 and is activated for protocol
 * versions >= 70012.
 */
public class SendHeadersMessage {

    /**
     * Build a 'sendheaders' message
     *
     * @param       peer            Destination peer
     * @return                      'sendheaders' message
     */
    public static Message buildSendHeadersMessage(Peer peer) {
        ByteBuffer buffer = MessageHeader.buildMessage("sendheaders", new byte[0]);
        return new Message(buffer, peer, MessageHeader.MessageCommand.SENDHEADERS);
    }

    /**
     * Process a 'sendheaders' message
     *
     * @param       msg             Message
     * @param       inBuffer        Input buffer
     * @param       msgListener     Message listener
     */
    public static void processSendHeadersMessage(Message msg, SerializedBuffer inBuffer, MessageListener msgListener) {
        //
        // Notify the message listener
        //
        msgListener.processSendHeaders(msg);
    }
}
