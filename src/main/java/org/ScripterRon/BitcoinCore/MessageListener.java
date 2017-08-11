/**
 * Copyright 2013-2017 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.BitcoinCore;

import java.util.List;

/**
 * A MessageListener is called during message processing to handle application-specific tasks.
 */
public interface MessageListener {

    /**
     * Handle an inventory request
     *
     * <p>This method is called when a 'getdata' message is received.  The application
     * should send the inventory items to the requesting peer.  A 'notfound' message
     * should be returned to the requesting peer if one or more items cannot be sent.</p>
     *
     * @param       msg             Message
     * @param       invList         Inventory item list
     */
    default public void sendInventory(Message msg, List<InventoryItem> invList) {
        // Default is to do nothing
    }

    /**
     * Handle an inventory item available notification
     *
     * <p>This method is called when an 'inv' message is received.  The application
     * should request any needed inventory items from the peer.</p>
     *
     * @param       msg             Message
     * @param       invList         Inventory item list
     */
    default public void requestInventory(Message msg, List<InventoryItem> invList) {
        // Default is to do nothing
    }

    /**
     * Handle a request not found
     *
     * <p>This method is called when a 'notfound' message is received.  It notifies the
     * application that an inventory request cannot be completed because the item was
     * not found.  The request can be discarded or retried by sending it to a different
     * peer.</p>
     *
     * @param       msg             Message
     * @param       invList         Inventory item list
     */
    default public void requestNotFound(Message msg, List<InventoryItem> invList) {
        // Default is to do nothing
    }

    /**
     * Handle a request for the transaction memory pool
     *
     * <p>This method is called when a 'mempool' message is received.  The application
     * should return an 'inv' message listing the transactions in the memory pool.</p>
     *
     * @param       msg             Message
     */
    default public void requestMemoryPool(Message msg) {
        // Default is to do nothing
    }

    /**
     * Process a peer address list
     *
     * <p>This method is called when an 'addr' message is received.</p>
     *
     * @param       msg             Message
     * @param       addresses       Peer address list
     */
    default public void processAddresses(Message msg, List<PeerAddress> addresses) {
        // Default is to do nothing
    }

    /**
     * Process an alert
     *
     * <p>This method is called when an 'alert' message is received.</p>
     *
     * @param       msg             Message
     * @param       alert           Alert
     */
    default public void processAlert(Message msg, Alert alert) {
        // Default is to do nothing
    }

    /**
     * Process a block
     *
     * <p>This method is called when a 'block' message is received.</p>
     *
     * @param       msg             Message
     * @param       block           Block
     */
    default public void processBlock(Message msg, Block block) {
        // Default is to do nothing
    }

    /**
     * Process a block header
     *
     * <p>This method is called when a 'headers' message is received.</p>
     *
     * @param       msg             Message
     * @param       hdrList         Block header list
     */
    default public void processBlockHeaders(Message msg, List<BlockHeader> hdrList) {
        // Default is to do nothing
    }

    /**
     * Process block transactions
     *
     * <p>This method is called when a 'blocktxn' message is received.</p>
     *
     * @param       msg             Message
     * @param       blockHash       Block identifier
     * @param       txList          Transactions
     */
    default public void processBlockTransactions(Message msg, Sha256Hash blockHash, List<Transaction> txList) {
        // Default is to do nothing
    }

    /**
     * Process a compact block
     *
     * <p>This method is called when a 'cmpctblock' message is received.</p>
     *
     * @param       msg             Message
     * @param       header          Block header
     * @param       nonce           Transaction nonce
     * @param       shortIds        Short transaction identifiers
     * @param       prefilledTxs    Prefilled transactions
     */
    default public void processCompactBlock(Message msg, BlockHeader header, long nonce, List<Long> shortIds,
                                    List<CompactBlockMessage.PrefilledTransaction> prefilledTxs) {
        // Default is to do nothing
    }
    
    /**
     * Process a fee filter message
     * 
     * <p>This method is called when a 'feefilter' message is received.</p>
     * 
     * @param       msg             Message
     * @param       fee             Minimum fee (satoshis/byte)
     */
    default public void processFeeFilter(Message msg, long fee) {
        // Default is to do nothing
    }

    /**
     * Process a Bloom filter clear request
     *
     * <p>This method is called when a 'filterclear' message is received.  The peer
     * Bloom filter has been cleared before this method is called.</p>
     *
     * @param       msg             Message
     * @param       oldFilter       Previous bloom filter
     */
    default public void processFilterClear(Message msg, BloomFilter oldFilter) {
        // Default is to do nothing
    }

    /**
     * Process a Bloom filter load request
     *
     * <p>This method is called when a 'filterload' message is received.  The peer Bloom
     * filter has been updated before this method is called.</p>
     *
     * @param       msg             Message
     * @param       oldFilter       Previous bloom filter
     * @param       newFilter       New bloom filter
     */
    default public void processFilterLoad(Message msg, BloomFilter oldFilter, BloomFilter newFilter) {
        // Default is to do nothing
    }

    /**
     * Process a get address request
     *
     * <p>This method is called when a 'getaddr' message is received.  The application should
     * call AddressMessage.buildAddressMessage() to build the response message.</p>
     *
     * @param       msg             Message
     */
    default public void processGetAddress(Message msg) {
        // Default is to do nothing
    }

    /**
     * Process a request for the latest blocks
     *
     * <p>This method is called when a 'getblocks' message is received.  The application should
     * use the locator block list to find the latest common block and then send an 'inv'
     * message to the peer for the blocks following the common block.</p>
     *
     * @param       msg             Message
     * @param       version         Negotiated version
     * @param       blockList       Locator block list
     * @param       stopBlock       Stop block (Sha256Hash.ZERO_HASH if all blocks should be sent)
     */
    default public void processGetBlocks(Message msg, int version, List<Sha256Hash> blockList, Sha256Hash stopBlock) {
        // Default is to do nothing
    }

    /**
     * Process a request for block transactions
     *
     * <p>This method is called when a 'getblocktxn' message is received.  The application
     * should use the index list to get the requested transactions for the specified block
     * and then send a 'blocktxn' message to the peer.</p>
     *
     * @param       msg             Message
     * @param       blockHash       Block identifier
     * @param       indexes         List of transaction indexes
     */
    default public void processGetBlockTransactions(Message msg, Sha256Hash blockHash, List<Integer> indexes) {
        // Default is to do nothing
    }

    /**
     * Process a request for the latest headers
     *
     * <p>This method is called when a 'getheaders' message is received.  The application should
     * use the locator block list to find the latest common block and then send a 'headers'
     * message to the peer for the blocks following the common block.</p>
     *
     * @param       msg             Message
     * @param       version         Negotiated version
     * @param       blockList       Locator block list
     * @param       stopBlock       Stop block (Sha256Hash.ZERO_HASH if all blocks should be sent)
     */
    default public void processGetHeaders(Message msg, int version, List<Sha256Hash> blockList, Sha256Hash stopBlock) {
        // Default is to do nothing
    }

    /**
     * Process a Merkle block
     *
     * <p>This method is called when a 'merkleblock' message is received.</p>
     *
     * @param       msg             Message
     * @param       blkHeader       Merkle block header
     */
    default public void processMerkleBlock(Message msg, BlockHeader blkHeader) {
        // Default is to do nothing
    }

    /**
     * Process a ping
     *
     * <p>This method is called when a 'ping' message is received.  The application should
     * return a 'pong' message to the sender.  This method will not be called if the sender
     * has not implemented BIP0031.</p>
     *
     * @param       msg             Message
     * @param       nonce           Nonce
     */
    default public void processPing(Message msg, long nonce) {
        // Default is to do nothing
    }

    /**
     * Process a pong
     *
     * <p>This method is called when a 'pong' message is received.</p>
     *
     * @param       msg             Message
     * @param       nonce           Nonce
     */
    default public void processPong(Message msg, long nonce) {
        // Default is to do nothing
    }

    /**
     * Process a message rejection
     *
     * <p>This method is called when a 'reject' message is received.</p>
     *
     * @param       msg             Message
     * @param       cmd             Failing message command
     * @param       reasonCode      Failure reason code
     * @param       description     Description of the failure
     * @param       hash            Item hash or Sha256Hash.ZERO_HASH
     */
    default public void processReject(Message msg, String cmd, int reasonCode, String description, Sha256Hash hash) {
        // Default is to do nothing
    }

    /**
     * Process the send compact notification
     *
     * <p>This method is called when a 'sendcmpct' message is received.</p>
     *
     * @param       msg             Message
     * @param       enabled         TRUE if compact block support is enabled
     * @param       version         Compact block version
     */
    default public void processSendCompact(Message msg, boolean enabled, long version) {
        // Default is to do nothing
    }

    /**
     * Process the send headers notification
     *
     * <p>This method is called when a 'sendheaders' message is received.</p>
     *
     * @param       msg             Message
     */
    default public void processSendHeaders(Message msg) {
        // Default is to do nothing
    }

    /**
     * Process a transaction
     *
     * <p>This method is called when a 'tx' message is received.</p>
     *
     * @param       msg             Message
     * @param       tx              Transaction
     */
    default public void processTransaction(Message msg, Transaction tx) {
        // Default is to do nothing
    }

    /**
     * Process a version message
     *
     * <p>This method is called when a 'version' message is received.  The application
     * should return a 'verack' message to the sender if the connection is accepted.</p>
     *
     * @param       msg             Message
     * @param       localAddress    Local address as seen by the peer
     */
    default public void processVersion(Message msg, PeerAddress localAddress) {
        // Default is to do nothing
    }

    /**
     * Process a version acknowledgment
     *
     * <p>This method is called when a 'verack' message is received.</p>
     *
     * @param       msg             Message
     */
    default public void processVersionAck(Message msg) {
        // Default is to do nothing
    }
}
