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

import java.util.HashMap;
import java.util.Map;

/**
 * Manage the HD key hierarchy (BIP 32)
 *
 *                      +----------------- Root ------------------+
 *                      |                  (m)                    |
 *                      |                                         |
 *             +----- Account-0 -----+     ...           +----- Account-n -----+
 *             |       (m/0)         |                   |      (m/n)          |
 *             |                     |                   |                     |
 *      +--- Chain-0 ---+ ... +--- Chain-n ---+     +--- Chain-0 ---+ ... +--- Chain-n ---+
 *      |    (m/0/0)    |     |    (m/0/n)    |     |    (m/n/0)    |     |    (m/n/n)    |
 *      |               |     |               |     |               |     |               |
 *    key-0   ...     key-n key-0   ...     key-n key-0 ...       key-n key-0   ...     key-n
 *
 * An account key is a child of the root key.  Each account has one or more chain
 * keys.  Each chain key has one or more application keys.  Each key contains a
 * list of child keys (if any).
 */
public class HDHierarchy {

    /** Root key */
    private final HDKey rootKey;

    /** Root node */
    private final Node rootNode;

    /**
     * Create a new hierarchy
     *
     * @param   rootKey             Root key
     */
    public HDHierarchy(HDKey rootKey) {
        this.rootKey = rootKey;
        this.rootNode = new Node(rootKey);
        rootKey.setNode(this.rootNode);
    }

    /**
     * Return the root key
     *
     * @return                      Root key
     */
    public HDKey getRootKey() {
        return rootKey;
    }

    /**
     * Derive a child key
     *
     * An existing key will be returned if it is found in the key hierarchy.
     *
     * @param   parent                  Parent key
     * @param   childNumber             Child number
     * @param   hardened                TRUE to harden the child
     * @return                          Derived key
     * @throws  HDDerivationException   Unable to derive the key
     */
    public HDKey deriveChildKey(HDKey parent, int childNumber, boolean hardened)
                                        throws HDDerivationException {
        if ((childNumber&HDKey.HARDENED_FLAG) != 0)
            throw new IllegalArgumentException("Hardened flag must not be set in child number");
        Node parentNode = parent.getNode();
        //
        // Return an existing key
        //
        if (parentNode != null) {
            HDKey childKey = parentNode.getChildKey(childNumber);
            if (childKey != null) {
                return childKey;
            }
        }
        //
        // Derive the child key
        //
        HDKey childKey = HDKeyDerivation.deriveChildKey(parent, childNumber, hardened);
        //
        // Add the derived key as a child of the parent key
        //
        if (parentNode == null) {
            parentNode = new Node(parent);
            parent.setNode(parentNode);
        }
        parentNode.addChildKey(childKey);
        return childKey;
    }

    /**
     * Hierarchy node
     */
    public class Node {

        /** Key for this node */
        private final HDKey key;

        /** Children associated with this node */
        private final Map<Integer, HDKey> children = new HashMap<>();

        /**
         *
         * Create a new node
         *
         * @param   key                 Key for this node
         */
        Node(HDKey key) {
            this.key = key;
        }

        /**
         * Add a child key
         *
         * @param   childKey            Child key to add
         */
        void addChildKey(HDKey childKey) {
            children.put(childKey.getChildNumber(), childKey);
        }

        /**
         * Return the node key
         *
         * @return                      Node key
         */
        public HDKey getKey() {
            return key;
        }

        /**
         * Return a child key
         *
         * @param   childNumber         Child number
         * @return                      Child key or null if the key doesn't exist
         */
        public HDKey getChildKey(int childNumber) {
            return children.get(childNumber);
        }
    }
}
