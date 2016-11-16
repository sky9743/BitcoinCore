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

/**
 * The 'sendcmpct' message notifies the peer that compact blocks are supported.
 *
 * The 'sendcmpct' message is defined in BIP 152 and is activated for protocol
 * versions >= 70014.
 *
 * <p>SendCompact Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   1 byte     Flag            TRUE to enable compact block support
 *   8 byte     Version         Compact block support version
 * </pre>
 */
public class SendCompactMessage {

    /**
     * Build a 'sendcmpct' message
     *
     * @param       peer            Destination peer
     * @param       enabled         TRUE to enable compact block support
     * @param       version         Compact block version
     * @return                      'sendcmpct' message
     */
    public static Message buildSendCompactMessage(Peer peer, boolean enabled, long version) {
         //
        // Build the message data
        //
        SerializedBuffer msgBuffer = new SerializedBuffer();
        msgBuffer.putBoolean(enabled);
        msgBuffer.putLong(version);
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("sendcmpct", msgBuffer);
        return new Message(buffer, peer, MessageHeader.MessageCommand.SENDCMPCT);
    }

    /**
     * Process a 'sendcmpct' message
     *
     * @param       msg             Message
     * @param       inBuffer        Input buffer
     * @param       msgListener     Message listener
     * @throws      EOFException    Serialized byte stream is too short
     */
    public static void processSendCompactMessage(Message msg, SerializedBuffer inBuffer, MessageListener msgListener)
                                    throws EOFException {
        //
        // Get the message data
        //
        boolean enabled = inBuffer.getBoolean();
        long version = inBuffer.getLong();
        //
        // Notify the message listener
        //
        msgListener.processSendCompact(msg, enabled, version);
    }
}
