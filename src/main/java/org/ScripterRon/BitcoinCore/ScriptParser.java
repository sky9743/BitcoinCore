/*
 * Copyright 2014-2016 Ronald W Hoffman.
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
import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;

/**
 * Transaction script parser
 *
 * A script is a small program contained in the transaction which determines whether or not
 * an output can be spent.  The first half of the script is provided by the transaction input
 * and the second half of the script is provided by the connected transaction output.
 */
public class ScriptParser {

    /** Verbose debug flag */
    private static final boolean verboseDebug = false;

    /** OP_CHECKLOCKTIMEVERIFY flag (BIP 65) */
    private static final int OP_CLTV_ENABLED = 1;

    /** OP_CHECKSEQUENCEVERIFY flag (BIP 112) */
    private static final int OP_CSV_ENABLED = 1;

    /**
     * Processes a transaction script to determine if the spending transaction
     * is authorized to spend the output coins
     *
     * @param       txInput             Transaction input spending the coins
     * @param       txOutput            Transaction output providing the coins
     * @param       blockTimestamp      Block timestamp (cannot be before Jan 3, 2009 - 1230940800)
     * @return                          The script result
     * @throws      ScriptException     Unable to process the transaction script
     */
    public static boolean process(TransactionInput txInput, TransactionOutput txOutput, long blockTimestamp)
                                        throws ScriptException {
        if (blockTimestamp < 1230940800L)
            throw new IllegalArgumentException("Block timestamp is not valid");
        int scriptFlags = 0;
        if (blockTimestamp > 1444795200L)
            scriptFlags |= OP_CLTV_ENABLED;
        if (blockTimestamp > 1462060800L && !txInput.getTransaction().isCoinBase())
            scriptFlags |= OP_CSV_ENABLED;
        txInput.setValue(txOutput.getValue());
        Transaction tx = txInput.getTransaction();
        boolean txValid = true;
        boolean witnessInput = tx.isWitness() && !tx.getWitness().get(txInput.getIndex()).getWitness().isEmpty();
        List<byte[]> scriptStack = new ArrayList<>(5);
        List<StackElement> elemStack = new ArrayList<>(25);
        List<StackElement> altStack = new ArrayList<>(5);
        byte[] inputScriptBytes = txInput.getScriptBytes();
        byte[] outputScriptBytes = txOutput.getScriptBytes();
        //
        // Check for a native witness program (BIP 141)
        //
        // Version 0 is either P2WPKH or P2WSH as determined by the program length.
        // Non-zero versions are reserved for future use and are ignored.
        //
        if (witnessInput) {
            byte[][] result = Script.getWitnessProgram(outputScriptBytes);
            if (result != null) {
                if (inputScriptBytes.length != 0)
                    throw new ScriptException(
                            "Non-empty ScriptSig for native witness program\n Tx " + tx.getHashAsString());
                int version = result[0][0];
                byte[] witnessBytes = result[1];
                if (version != 0)
                    return true;
                TransactionWitness txWitness = tx.getWitness().get(txInput.getIndex());
                if (witnessBytes.length == 20) {
                    if (txWitness.getWitness().size() != 2)
                        throw new ScriptException(
                                "Witness data count is not 2 for P2WPKH\n Tx " + tx.getHashAsString());
                    byte[] pubKey = txWitness.getWitness().get(1);
                    if (pubKey[0] != 0x02 && pubKey[0] != 0x03)
                        throw new ScriptException(
                                "Public key is not compressed for P2WPKH\n Tx " + tx.getHashAsString());
                    inputScriptBytes = txWitness.getScriptSig();
                    outputScriptBytes = Script.getScriptPubKey(Address.AddressType.P2PKH, witnessBytes, false);
                } else {
                    if (txWitness.getWitness().isEmpty())
                        throw new ScriptException(
                                "No witness data for P2WSH\n Tx " + tx.getHashAsString());
                    inputScriptBytes = txWitness.getScriptSig();
                    outputScriptBytes = Script.getScriptPubKey(Address.AddressType.P2SH, Utils.hash160(witnessBytes), false);
                }
            }
        }
        //
        // Create the script stack
        //
        if (inputScriptBytes.length != 0)
            scriptStack.add(inputScriptBytes);
        if (outputScriptBytes.length != 0)
            scriptStack.add(outputScriptBytes);
        if (verboseDebug)
            System.out.printf("Processing scripts for transaction %s\n", tx.getHashAsString());
        //
        // The result is FALSE if there are no scripts to process since an empty stack
        // is the same as FALSE
        //
        if (scriptStack.isEmpty())
            return false;
        //
        // Process the script segments
        //
        try {
            boolean p2sh = false;
            while (txValid && !scriptStack.isEmpty()) {
                //
                // Process the top script segment
                //
                txValid = processScript(txInput, scriptStack, elemStack, altStack, p2sh, scriptFlags);
                scriptStack.remove(0);
                //
                // Check for P2SH witness program (BIP 141)
                //
                if (witnessInput && txValid && p2sh && !scriptStack.isEmpty()) {
                    byte[] scriptBytes = scriptStack.get(0);
                    byte[][] result = Script.getWitnessProgram(scriptBytes);
                    if (result != null) {
                        scriptStack.remove(0);
                        if (!elemStack.isEmpty())
                            throw new ScriptException(
                                    "Non-empty element stack for P2SH witness program\n Tx " + tx.getHashAsString());
                        int version = result[0][0];
                        byte[] witnessBytes = result[1];
                        if (version != 0)
                            return true;
                        TransactionWitness txWitness = tx.getWitness().get(txInput.getIndex());
                        if (witnessBytes.length == 20) {
                            if (txWitness.getWitness().size() != 2)
                                throw new ScriptException(
                                        "Witness data count is not 2 for P2WPKH\n Tx " + tx.getHashAsString());
                            byte[] pubKey = txWitness.getWitness().get(1);
                            if (pubKey[0] != 0x02 && pubKey[0] != 0x03)
                                throw new ScriptException(
                                        "Public key is not compressed for P2WPKH\n Tx " + tx.getHashAsString());
                            scriptStack.add(txWitness.getScriptSig());
                            scriptStack.add(Script.getScriptPubKey(Address.AddressType.P2PKH, witnessBytes, false));
                        } else {
                            if (txWitness.getWitness().isEmpty())
                                throw new ScriptException(
                                        "No witness data for P2WSH\n Tx " + tx.getHashAsString());
                            scriptStack.add(txWitness.getScriptSig());
                            scriptStack.add(Script.getScriptPubKey(Address.AddressType.P2SH, Utils.hash160(witnessBytes), false));
                        }
                    }
                }
                //
                // Check if the next script is P2SH (BIP 16 requires block timestamp >= 1333238400)
                //
                if (txValid && !scriptStack.isEmpty() && blockTimestamp >= 1333238400L) {
                    byte[] scriptBytes = scriptStack.get(0);
                    p2sh = (scriptBytes.length == 23 &&
                            scriptBytes[0] == (byte)ScriptOpCodes.OP_HASH160 &&
                            scriptBytes[1] == 20 &&
                            scriptBytes[22] == (byte)ScriptOpCodes.OP_EQUAL &&
                            !elemStack.isEmpty());
                }
            }
        } catch (Throwable exc) {
            throw new ScriptException(String.format("%s: %s\n  Tx %s\n  Index %d",
                                      exc.getClass().getName(), exc.getMessage(),
                                      tx.getHash().toString(), txInput.getIndex()), exc);
        }
        //
        // The script is successful if a non-zero value is on the top of the stack.  An
        // empty stack is the same as a FALSE value.
        //
        if (txValid)
            txValid = (!elemStack.isEmpty() ? popStack(elemStack).isTrue() : false);
        return txValid;
    }

    /**
     * Processes the current script
     *
     * @param       txInput             The current transaction input
     * @param       scriptStack         Script stack
     * @param       elemStack           Element stack
     * @param       altStack            Alternate stack
     * @param       p2sh                TRUE if this is a pay-to-script-hash
     * @param       scriptFlags         Enabled script features
     * @return                          Script result
     * @throws      EOFException        End-of-data processing script
     * @throws      ScriptException     Unable to process script
     */
    private static boolean processScript(TransactionInput txInput, List<byte[]> scriptStack,
                                        List<StackElement> elemStack, List<StackElement> altStack,
                                        boolean p2sh, int scriptFlags) throws EOFException, ScriptException {
        boolean txValid = true;
        boolean skipping;
        byte[] scriptBytes = scriptStack.get(0);
        int offset = 0;
        int lastSeparator = 0;
        Deque<Boolean> ifStack = new ArrayDeque<>();
        if (verboseDebug)
            System.out.println("Processing script segment");
        //
        // Process the script opcodes
        //
        while (txValid && offset<scriptBytes.length) {
            StackElement elem, elem1, elem2, elem3, elem4;
            BigInteger big1, big2, big3;
            byte[] bytes;
            int dataToRead, size, index;
            int opcode = (int)scriptBytes[offset++]&0xff;
            if (verboseDebug)
                System.out.printf("Processing OpCode %02X\n", opcode);
            skipping = !ifStack.isEmpty() && !ifStack.peek();
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                // Data push opcodes
                int[] result = Script.getDataLength(opcode, scriptBytes, offset);
                dataToRead = result[0];
                offset = result[1];
                if (offset+dataToRead > scriptBytes.length)
                    throw new EOFException("End-of-data while processing script");
                if (!skipping) {
                    bytes = new byte[dataToRead];
                    if (dataToRead > 0)
                        System.arraycopy(scriptBytes, offset, bytes, 0, dataToRead);
                    elemStack.add(new StackElement(bytes));
                }
                offset += dataToRead;
            } else if (opcode == ScriptOpCodes.OP_IF) {
                // IF clause processed if top stack element is true
                ifStack.push(skipping ? false : popStack(elemStack).isTrue());
                if (verboseDebug)
                    System.out.printf("OP_IF(%d) status %s\n", ifStack.size(), ifStack.peek());
            } else if (opcode == ScriptOpCodes.OP_NOTIF) {
                // IF clause process if top stack element is false
                ifStack.push(skipping ? false : !popStack(elemStack).isTrue());
                if (verboseDebug)
                    System.out.printf("OP_NOTIF(%d) status %s\n", ifStack.size(), ifStack.peek());
            } else if (opcode == ScriptOpCodes.OP_ENDIF) {
                // IF processing completed
                if (ifStack.isEmpty())
                    throw new ScriptException("OP_ENDIF without matching OP_IF");
                if (verboseDebug)
                    System.out.printf("IF(%d) ended\n", ifStack.size());
                ifStack.pop();
            } else if (opcode == ScriptOpCodes.OP_ELSE) {
                if (ifStack.isEmpty())
                    throw new ScriptException("OP_ELSE without matching OP_IF");
                ifStack.pop();
                if (ifStack.isEmpty() || ifStack.peek())
                    ifStack.push(skipping);
                else
                    ifStack.push(false);
                if (verboseDebug)
                    System.out.printf("OP_ELSE status %s\n", ifStack.peek());
            } else if (skipping) {
                // We are skipping, so don't execute opcodes
                if (verboseDebug)
                    System.out.println("Skipping OpCode");
            } else if (opcode >= ScriptOpCodes.OP_1 && opcode <= ScriptOpCodes.OP_16) {
                // Push 1 to 16 onto the stack based on the opcode (0x51-0x60)
                bytes = new byte[1];
                bytes[0] = (byte)(opcode&0x0f);
                if (bytes[0] == 0)
                    bytes[0] = (byte)16;
                elemStack.add(new StackElement(bytes));
            } else {
                switch (opcode) {
                    case ScriptOpCodes.OP_NOP:
                    case ScriptOpCodes.OP_NOP1:
                    case ScriptOpCodes.OP_NOP4:
                    case ScriptOpCodes.OP_NOP5:
                    case ScriptOpCodes.OP_NOP6:
                    case ScriptOpCodes.OP_NOP7:
                    case ScriptOpCodes.OP_NOP8:
                    case ScriptOpCodes.OP_NOP9:
                    case ScriptOpCodes.OP_NOP10:
                        // Do nothing
                        break;
                    case ScriptOpCodes.OP_RETURN:
                        // Mark transaction invalid
                        txValid = false;
                        break;
                    case ScriptOpCodes.OP_CODESEPARATOR:
                        // Signature operations ignore data before the separator
                        lastSeparator = offset;
                        break;
                    case ScriptOpCodes.OP_1NEGATE:
                        // Push -1 onto the stack
                        elemStack.add(new StackElement(BigInteger.ONE.negate()));
                        break;
                    case ScriptOpCodes.OP_NOT:
                        // Reverse the top stack element (TRUE->FALSE, FALSE->TRUE)
                        elemStack.add(new StackElement(!popStack(elemStack).isTrue()));
                        break;
                    case ScriptOpCodes.OP_0NOTEQUAL:
                        // Returns 0 if the input is 0, otherwise returns 1
                        elemStack.add(new StackElement(popStack(elemStack).isTrue()));
                        break;
                    case ScriptOpCodes.OP_GREATERTHAN:
                        // Returns 1 if element A is greater than element B
                        big1 = popStack(elemStack).getBigInteger();     // B
                        big2 = popStack(elemStack).getBigInteger();     // A
                        elemStack.add(new StackElement(big2.compareTo(big1)>0));
                        break;
                    case ScriptOpCodes.OP_LESSTHAN:
                        // Returns 1 if element A is less than element B
                        big1 = popStack(elemStack).getBigInteger();     // B
                        big2 = popStack(elemStack).getBigInteger();     // A
                        elemStack.add(new StackElement(big2.compareTo(big1)<0));
                        break;
                    case ScriptOpCodes.OP_GREATERTHANOREQUAL:
                        // Returns 1 if element A is greater than or equal to element B
                        big1 = popStack(elemStack).getBigInteger();     // B
                        big2 = popStack(elemStack).getBigInteger();     // A
                        elemStack.add(new StackElement(big2.compareTo(big1)>=0));
                        break;
                    case ScriptOpCodes.OP_LESSTHANOREQUAL:
                        // Returns 1 if element A is less than or equal to element B
                        big1 = popStack(elemStack).getBigInteger();     // B
                        big2 = popStack(elemStack).getBigInteger();     // A
                        elemStack.add(new StackElement(big2.compareTo(big1)<=0));
                        break;
                    case ScriptOpCodes.OP_ADD:
                        // Add the top stack elements
                        big1 = popStack(elemStack).getBigInteger();
                        big2 = popStack(elemStack).getBigInteger();
                        elemStack.add(new StackElement(big2.add(big1)));
                        break;
                    case ScriptOpCodes.OP_1ADD:
                        // Add one to the top stack element
                        elemStack.add(new StackElement(popStack(elemStack).getBigInteger().add(BigInteger.ONE)));
                        break;
                    case ScriptOpCodes.OP_SUB:
                        // Subtract the top stack elements
                        big1 = popStack(elemStack).getBigInteger();
                        big2 = popStack(elemStack).getBigInteger();
                        elemStack.add(new StackElement(big2.subtract(big1)));
                        break;
                    case ScriptOpCodes.OP_1SUB:
                        // Subtract one from the top stack element
                        elemStack.add(new StackElement(popStack(elemStack).getBigInteger().subtract(BigInteger.ONE)));
                        break;
                    case ScriptOpCodes.OP_MUL:
                        // Multiply the top stack elements
                        big1 = popStack(elemStack).getBigInteger();
                        big2 = popStack(elemStack).getBigInteger();
                        elemStack.add(new StackElement(big2.multiply(big1)));
                        break;
                    case ScriptOpCodes.OP_DIV:
                        // Divide the top stack elements
                        big1 = popStack(elemStack).getBigInteger();
                        big2 = popStack(elemStack).getBigInteger();
                        elemStack.add(new StackElement(big2.divide(big1)));
                        break;
                    case ScriptOpCodes.OP_NEGATE:
                        // Reverse the sign of the top stack element
                        elemStack.add(new StackElement(popStack(elemStack).getBigInteger().negate()));
                        break;
                    case ScriptOpCodes.OP_ABS:
                        // Get the absolute value of the top stack element
                        elemStack.add(new StackElement(popStack(elemStack).getBigInteger().abs()));
                        break;
                    case ScriptOpCodes.OP_MIN:
                        // Compare top 2 stack elements and replace with the smaller
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        elemStack.add(elem1.compareTo(elem2)<=0 ? elem1 : elem2);
                        break;
                    case ScriptOpCodes.OP_MAX:
                        // Compare top 2 stack elements and replace with the larger
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        elemStack.add(elem1.compareTo(elem2)>=0 ? elem1 : elem2);
                        break;
                    case ScriptOpCodes.OP_WITHIN:
                        // Return TRUE if the value is within the min/max values
                        big1 = popStack(elemStack).getBigInteger();         // MAX
                        big2 = popStack(elemStack).getBigInteger();         // MIN
                        big3 = popStack(elemStack).getBigInteger();         // VALUE
                        elemStack.add(new StackElement(big3.compareTo(big2)>=0 && big3.compareTo(big1)<0));
                        break;
                    case ScriptOpCodes.OP_NUMEQUAL:
                    case ScriptOpCodes.OP_NUMEQUALVERIFY:
                        // Compare the two top stack elements and return TRUE if they are equal
                        big1 = popStack(elemStack).getBigInteger();
                        big2 = popStack(elemStack).getBigInteger();
                        elemStack.add(new StackElement(big1.compareTo(big2)==0));
                        if (opcode == ScriptOpCodes.OP_NUMEQUALVERIFY)
                            txValid = processVerify(elemStack);
                        break;
                    case ScriptOpCodes.OP_NUMNOTEQUAL:
                        // Compare the two top stack elements and return TRUE if they are not equal
                        big1 = popStack(elemStack).getBigInteger();
                        big2 = popStack(elemStack).getBigInteger();
                        elemStack.add(new StackElement(big1.compareTo(big2)!=0));
                        break;
                    case ScriptOpCodes.OP_BOOLAND:
                        // Result is TRUE if two top elements are TRUE
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        elemStack.add(new StackElement(elem1.isTrue() && elem2.isTrue()));
                        break;
                    case ScriptOpCodes.OP_BOOLOR:
                        // Result is TRUE if at least one of the two top elements is TRUE
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        elemStack.add(new StackElement(elem1.isTrue() || elem2.isTrue()));
                        break;
                    case ScriptOpCodes.OP_TOALTSTACK:
                        // Move from main stack to alternate stack
                        altStack.add(popStack(elemStack));
                        break;
                    case ScriptOpCodes.OP_FROMALTSTACK:
                        // Move from alternate stack to main stack
                        elemStack.add(popStack(altStack));
                        break;
                    case ScriptOpCodes.OP_DROP:
                        // Remove the top stack element
                        popStack(elemStack);
                        break;
                    case ScriptOpCodes.OP_2DROP:
                        // Remove the top two stack elements
                        popStack(elemStack);
                        popStack(elemStack);
                        break;
                    case ScriptOpCodes.OP_NIP:
                        // Remove the second-from-top stack element
                        size = elemStack.size();
                        if (size < 2)
                            throw new ScriptException("Stack underrun on OP_NIP");
                        elemStack.remove(size-2);
                        break;
                    case ScriptOpCodes.OP_OVER:
                        // Copy the second-from-top stack element to the top of the stack
                        size = elemStack.size();
                        if (size<2)
                            throw new ScriptException("Stack underrun on OP_OVER");
                        elemStack.add(elemStack.get(size-2));
                        break;
                    case ScriptOpCodes.OP_2OVER:
                        // Copy the pair of elements behind the top pair to the top of the stack
                        size = elemStack.size();
                        if (size < 4)
                            throw new ScriptException("Stack underrun on OP_2OVER");
                        elem1 = elemStack.get(size-4);
                        elem2 = elemStack.get(size-3);
                        elemStack.add(elem1);
                        elemStack.add(elem2);
                        break;
                    case ScriptOpCodes.OP_PICK:
                        // Copy the nth-from-top stack element to the top of the stack
                        index = popStack(elemStack).getBigInteger().intValue();
                        size = elemStack.size();
                        if (index >= size)
                            throw new ScriptException("Stack underrun on OP_PICK");
                        elemStack.add(elemStack.get(size-index-1));
                        break;
                    case ScriptOpCodes.OP_ROLL:
                        // Move the nth-from-top stack element to the top of the stack
                        index = popStack(elemStack).getBigInteger().intValue();
                        size = elemStack.size();
                        if (index >= size)
                            throw new ScriptException("Stack underrun on OP_ROLL");
                        elemStack.add(elemStack.remove(size-index-1));
                        break;
                    case ScriptOpCodes.OP_ROT:
                        // Rotate the top three stack elements
                        size = elemStack.size();
                        if (size < 3)
                            throw new ScriptException("Stack underrun on OP_ROT");
                        elemStack.add(elemStack.remove(size-3));
                        break;
                    case ScriptOpCodes.OP_2ROT:
                        // Rotate the top three pairs of stack elements
                        size = elemStack.size();
                        if (size < 6)
                            throw new ScriptException("Stack overrun on OP2ROT");
                        elemStack.add(elemStack.remove(size-6));
                        elemStack.add(elemStack.remove(size-6));
                        break;
                    case ScriptOpCodes.OP_TUCK:
                        // Copy the top stack element before the second-from-top element
                        size = elemStack.size();
                        if (size < 2)
                            throw new ScriptException("Stack underrun on OP_TUCK");
                        elemStack.add(size-2, elemStack.get(size-1));
                        break;
                    case ScriptOpCodes.OP_DUP:
                        // Duplicate the top stack element
                        elemStack.add(new StackElement(peekStack(elemStack)));
                        break;
                    case ScriptOpCodes.OP_2DUP:
                        // Duplicate the top two stack elements
                        size = elemStack.size();
                        if (size < 2)
                            throw new ScriptException("Stack underron on OP_2DUP");
                        elemStack.add(elemStack.get(size-2));
                        elemStack.add(elemStack.get(size-1));
                        break;
                    case ScriptOpCodes.OP_3DUP:
                        // Duplicate the top three stack elements
                        size = elemStack.size();
                        if (size < 3)
                            throw new ScriptException("Stack underron on OP_3DUP");
                        elemStack.add(elemStack.get(size-3));
                        elemStack.add(elemStack.get(size-2));
                        elemStack.add(elemStack.get(size-1));
                        break;
                    case ScriptOpCodes.OP_IFDUP:
                        // Duplicate top stack element if it is not zero
                        elem = peekStack(elemStack);
                        if (elem.isTrue())
                            elemStack.add(new StackElement(elem));
                        break;
                    case ScriptOpCodes.OP_SWAP:
                        // Swap the top two elements
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        elemStack.add(elem1);
                        elemStack.add(elem2);
                        break;
                    case ScriptOpCodes.OP_2SWAP:
                        // Swap the top two pairs of elements
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        elem3 = popStack(elemStack);
                        elem4 = popStack(elemStack);
                        elemStack.add(elem2);
                        elemStack.add(elem1);
                        elemStack.add(elem4);
                        elemStack.add(elem3);
                        break;
                    case ScriptOpCodes.OP_DEPTH:
                        // Push the stack depth
                        elemStack.add(new StackElement(BigInteger.valueOf(elemStack.size())));
                        break;
                    case ScriptOpCodes.OP_SIZE:
                        // Push the size of the top stack element
                        elemStack.add(new StackElement(BigInteger.valueOf(peekStack(elemStack).getBytes().length)));
                        break;
                    case ScriptOpCodes.OP_VERIFY:
                        // Verify the top stack element
                        txValid = processVerify(elemStack);
                        break;
                    case ScriptOpCodes.OP_EQUAL:
                    case ScriptOpCodes.OP_EQUALVERIFY:
                        // Push 1 (TRUE) if top two stack elements are equal, else push 0 (FALSE)
                        bytes = new byte[1];
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        if (elem1.equals(elem2))
                            bytes[0] = (byte)1;
                        elemStack.add(new StackElement(bytes));
                        if (opcode == ScriptOpCodes.OP_EQUAL) {
                            if (p2sh && scriptStack.size()>1 && bytes[0]==1) {
                                // Remove TRUE from the stack so that we are left with just the remaining
                                // data elements from the input script (OP_EQUAL is the last opcode
                                // in the output script)
                                popStack(elemStack);
                            }
                        } else {
                            txValid = processVerify(elemStack);
                        }
                        break;
                    case ScriptOpCodes.OP_RIPEMD160:
                        // RIPEMD160 hash of the top stack element
                        elemStack.add(new StackElement(Utils.hash160(popStack(elemStack).getBytes())));
                        break;
                    case ScriptOpCodes.OP_SHA1:
                        // SHA-1 hash of top stack element
                        elemStack.add(new StackElement(Utils.sha1Hash(popStack(elemStack).getBytes())));
                        break;
                    case ScriptOpCodes.OP_SHA256:
                        // SHA-256 hash of top stack element
                        elemStack.add(new StackElement(Utils.singleDigest(popStack(elemStack).getBytes())));
                        break;
                    case ScriptOpCodes.OP_HASH160:
                        // SHA-256 hash followed by RIPEMD160 hash of top stack element
                        elem = popStack(elemStack);
                        elemStack.add(new StackElement(Utils.sha256Hash160(elem.getBytes())));
                        // Save the deserialized script for pay-to-hash-script processing
                        if (p2sh && elem.getBytes().length>0)
                            scriptStack.add(elem.getBytes());
                        break;
                    case ScriptOpCodes.OP_HASH256:
                        // Double SHA-256 hash of top stack element
                        elemStack.add(new StackElement(Utils.doubleDigest(popStack(elemStack).getBytes())));
                        break;
                    case ScriptOpCodes.OP_CHECKSIG:
                    case ScriptOpCodes.OP_CHECKSIGVERIFY:
                        // Check single signature
                        processCheckSig(txInput, elemStack, scriptBytes, lastSeparator);
                        if (opcode == ScriptOpCodes.OP_CHECKSIGVERIFY)
                            txValid = processVerify(elemStack);
                        break;
                    case ScriptOpCodes.OP_CHECKMULTISIG:
                    case ScriptOpCodes.OP_CHECKMULTISIGVERIFY:
                        // Check multiple signatures
                        processMultiSig(txInput, elemStack, scriptBytes, lastSeparator);
                        if (opcode == ScriptOpCodes.OP_CHECKMULTISIGVERIFY)
                            txValid = processVerify(elemStack);
                        break;
                    case ScriptOpCodes.OP_CAT:
                    case ScriptOpCodes.OP_SUBSTR:
                    case ScriptOpCodes.OP_LEFT:
                    case ScriptOpCodes.OP_RIGHT:
                    case ScriptOpCodes.OP_INVERT:
                    case ScriptOpCodes.OP_AND:
                    case ScriptOpCodes.OP_OR:
                    case ScriptOpCodes.OP_XOR:
                    case ScriptOpCodes.OP_2MUL:
                    case ScriptOpCodes.OP_2DIV:
                    case ScriptOpCodes.OP_MOD:
                    case ScriptOpCodes.OP_LSHIFT:
                    case ScriptOpCodes.OP_RSHIFT:
                        // Disabled opcode
                        throw new ScriptException(String.format("Disabled script opcode %s (%d)",
                                                  ScriptOpCodes.getOpCodeName(opcode), opcode));
                    case ScriptOpCodes.OP_RESERVED:
                    case ScriptOpCodes.OP_RESERVED1:
                    case ScriptOpCodes.OP_RESERVED2:
                    case ScriptOpCodes.OP_VER:
                    case ScriptOpCodes.OP_VERIF:
                    case ScriptOpCodes.OP_VERNOTIF:
                        // Reserved opcodes allowed only when skipping
                        if (ifStack.isEmpty() || ifStack.peek()) {
                            throw new ScriptException(String.format("Reserved script opcode %s (%d)",
                                                      ScriptOpCodes.getOpCodeName(opcode), opcode));
                        }
                        break;
                    case ScriptOpCodes.OP_CHECKLOCKTIMEVERIFY:
                        if ((scriptFlags&OP_CLTV_ENABLED) != 0) {
                            if (elemStack.isEmpty()) {
                                txValid = false;
                            } else {
                                BigInteger threshold = BigInteger.valueOf(Transaction.LOCKTIME_THRESHOLD);
                                BigInteger txLockTime = BigInteger.valueOf(txInput.getTransaction().getLockTime());
                                BigInteger lockTime = peekStack(elemStack).getBigInteger();
                                int cmp1 = txLockTime.compareTo(threshold);
                                int cmp2 = lockTime.compareTo(threshold);
                                if (lockTime.signum() < 0 ||
                                        !((cmp1 < 0 && cmp2 < 0) || (cmp1 >= 0 && cmp2 >= 0)) ||
                                        lockTime.compareTo(txLockTime) > 0 || txInput.getSeqNumber() == -1) {
                                    txValid = false;
                                }
                            }
                        }
                        break;
                    case ScriptOpCodes.OP_CHECKSEQUENCEVERIFY:
                        if ((scriptFlags&OP_CSV_ENABLED) != 0) {
                            if (elemStack.isEmpty()) {
                                txValid = false;
                            } else {
                                BigInteger elemSequence = peekStack(elemStack).getBigInteger();
                                if (elemSequence.signum() < 0) {
                                    txValid = false;
                                } else {
                                    int txSequence = txInput.getSeqNumber();
                                    int sequence = elemSequence.intValue();
                                    int txType = txSequence&TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG;
                                    int type = sequence&TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG;
                                    if ((sequence&TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0) {
                                        if (txInput.getTransaction().getVersion() < 2 ||
                                                (txSequence&TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 ||
                                                type != txType ||
                                                (sequence&TransactionInput.SEQUENCE_LOCKTIME_MASK) >
                                                    (txSequence&TransactionInput.SEQUENCE_LOCKTIME_MASK)) {
                                            txValid = false;
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    default:
                        throw new ScriptException(String.format("Unsupported script opcode %s(%d)",
                                                  ScriptOpCodes.getOpCodeName(opcode), opcode));
                }
            }
        }
        return txValid;
    }

    /**
     * Returns the top element from the stack but does not remove it from the stack
     *
     * @param       elemStack           The element stack
     * @return                          The top stack element
     * @throws      ScriptException     The stack is empty
     */
    private static StackElement peekStack(List<StackElement> elemStack) throws ScriptException {
        if (elemStack.isEmpty())
            throw new ScriptException("Stack underrun");
        return elemStack.get(elemStack.size()-1);
    }

    /**
     * Pop the top element from the stack and return it
     *
     * @param       elemStack           The element stack
     * @return                          The top stack element
     * @throws      ScriptException     The stack is empty
     */
    private static StackElement popStack(List<StackElement> elemStack) throws ScriptException {
        if (elemStack.isEmpty())
            throw new ScriptException("Stack underrun");
        return elemStack.remove(elemStack.size()-1);
    }

    /**
     * Process OP_VERIFY
     *
     * Checks the top element on the stack and removes it if it is non-zero.  The return value
     * is TRUE if the top element is non-zero and FALSE otherwise.
     *
     * @param       elemStack           The element stack
     * @return                          TRUE if the top stack element is non-zero
     */
    private static boolean processVerify(List<StackElement> elemStack) {
        boolean txValid;
        int index = elemStack.size()-1;
        if (index < 0) {
            txValid = false;
        } else if (elemStack.get(index).isTrue()) {
            txValid = true;
            elemStack.remove(index);
        } else {
            txValid = false;
        }
        return txValid;
    }

    /**
     * Process OP_CHECKSIG
     *
     * The stack must contain the signature and the public key.  The public key is
     * used to verify the signature.  TRUE is pushed on the stack if the signature
     * is valid, otherwise FALSE is pushed on the stack.
     *
     * @param       txInput             The current transaction input
     * @param       elemStack           The element stack
     * @param       scriptBytes         The current script program
     * @param       lastSeparator       The last code separator offset or zero
     * @throws      ScriptException     Unable to verify signature
     */
    private static void processCheckSig(TransactionInput txInput, List<StackElement> elemStack,
                                        byte[] scriptBytes, int lastSeparator)
                                        throws ScriptException {
        byte[] bytes;
        boolean result;
        //
        // Check the signature
        //
        // Make sure the public key starts with x'02', x'03' or x'04'.  Otherwise,
        // Bouncycastle throws an illegal argument exception.  We will return FALSE
        // if we find an invalid public key.
        //
        StackElement pubKey = popStack(elemStack);
        StackElement sig = popStack(elemStack);
        //
        // The reference client returns FALSE for a zero-length signature
        //
        if (sig.getBytes().length == 0) {
            elemStack.add(new StackElement(false));
            return;
        }
        //
        // Check the signature
        //
        // The script subprogram starts following the last code separator and all instances
        // of the signature are removed
        //
        bytes = pubKey.getBytes();
        if (bytes.length == 0) {
            result = false;
        } else if (!ECKey.isPubKeyCanonical(bytes)) {
            result = false;
        } else {
            List<StackElement> pubKeys = new ArrayList<>();
            pubKeys.add(pubKey);
            byte[] subProgram = Script.removeDataElement(sig.getBytes(), scriptBytes, lastSeparator);
            result = checkSig(txInput, sig, pubKeys, subProgram);
        }
        //
        // Push the result on the stack
        //
        elemStack.add(new StackElement(result));
    }

    /**
     * Process OP_MULTISIG
     *
     * The stack must contain at least one signature and at least one public key.
     * Each public key is tested against each signature until a valid signature is
     * found.  All signatures must be verified but all public keys do not need to
     * be used.  A public key is removed from the list once it has been used to
     * verify a signature.
     *
     * TRUE is pushed on the stack if all signatures have been verified,
     * otherwise FALSE is pushed on the stack.
     *
     * @param       txInput             The current transaction input
     * @param       elemStack           The element stack
     * @param       scriptBytes         The current script program
     * @param       lastSeparator       The last code separator offset or zero
     * @throws      ScriptException     Unable to verify signature
     */
    private static void processMultiSig(TransactionInput txInput, List<StackElement> elemStack,
                                        byte[] scriptBytes, int lastSeparator)
                                        throws ScriptException {
        List<StackElement> keys = new ArrayList<>(20);
        List<StackElement> sigs = new ArrayList<>(20);
        boolean isValid = true;
        StackElement elem;
        byte[] bytes;
        //
        // Get the public keys
        //
        // Some transactions are storing application data as one of the public
        // keys.  So we need to check for a valid initial byte (02, 03, 04).
        // The garbage key will be ignored and the transaction will be valid as long
        // as the signature is verified using one of the valid keys.
        //
        int pubKeyCount = popStack(elemStack).getBigInteger().intValue();
        for (int i=0; i<pubKeyCount; i++) {
            elem = popStack(elemStack);
            bytes = elem.getBytes();
            if (bytes.length != 0 && ECKey.isPubKeyCanonical(bytes))
                keys.add(elem);
        }
        //
        // Get the signatures
        //
        int sigCount = popStack(elemStack).getBigInteger().intValue();
        for (int i=0; i<sigCount; i++)
            sigs.add(popStack(elemStack));
        //
        // Due to a bug in the reference client, an extra element is removed from the stack
        //
        popStack(elemStack);
        //
        // The script subprogram starts following the last code separator and all instances
        // of all signature are removed
        //
        byte[] subProgram = Arrays.copyOfRange(scriptBytes, lastSeparator, scriptBytes.length);
        for (StackElement sig : sigs)
            subProgram = Script.removeDataElement(sig.getBytes(), subProgram, 0);
        //
        // Verify each signature and stop if we have a verification failure
        //
        // We will stop when all signatures have been verified or there are no more
        // public keys available
        //
        for (StackElement sig : sigs) {
            if (keys.isEmpty()) {
                isValid = false;
                break;
            }
            isValid = checkSig(txInput, sig, keys, subProgram);
            if (!isValid)
                break;
        }
        //
        // Push the result on the stack
        //
        elemStack.add(new StackElement(isValid));
    }

    /**
     * Checks the transaction signature
     *
     * The signature is valid if it is signed by one of the supplied public keys.
     *
     * @param       txInput             The current transaction input
     * @param       sig                 The signature to be verified
     * @param       pubKeys             The public keys to be checked
     * @param       subProgram          The script subprogram
     * @return                          TRUE if the signature is valid, FALSE otherwise
     * @throw       ScriptException     Unable to verify signature
     */
    private static boolean checkSig(TransactionInput txInput, StackElement sig, List<StackElement> pubKeys,
                                        byte[] subProgram)  throws ScriptException {
        byte[] sigBytes = sig.getBytes();
        boolean isValid = false;
        if (sigBytes.length < 9)
            throw new ScriptException("Signature is too short");
        //
        // The hash type is the last byte of the signature.  Remove it and create a new
        // byte array containing the DER-encoded signature.
        //
        int hashType = (int)sigBytes[sigBytes.length-1]&0x00ff;
        byte[] encodedSig = new byte[sigBytes.length-1];
        System.arraycopy(sigBytes, 0, encodedSig, 0, encodedSig.length);
        //
        // Serialize the transaction
        //
        // The reference client has a bug for SIGHASH_SINGLE when the input index is
        // greater than or equal to the number of outputs.  In this case, it doesn't
        // detect an error and instead uses the error code as the transaction hash.
        // To handle this, we will set the serialized transaction data to null.  ECKey.verify()
        // will detect this and use the error hash when verifying the signature.
        //
        Transaction tx = txInput.getTransaction();
        byte[] txData;
        boolean witnessInput = tx.isWitness() && !tx.getWitness().get(txInput.getIndex()).getWitness().isEmpty();
        SerializedBuffer outBuffer = new SerializedBuffer(1024);
        if (!witnessInput &&
                (hashType&0x7f) != ScriptOpCodes.SIGHASH_SINGLE || txInput.getIndex() < tx.getOutputs().size()) {
            tx.serializeForSignature(txInput.getIndex(), hashType, subProgram, outBuffer);
            txData = outBuffer.toByteArray();
        } else {
            txData = null;
        }
        //
        // Use the public keys to verify the signature for the hashed data.  Stop as
        // soon as we have a verified signature.  The public key will be removed from
        // the list if it verifies a signature to prevent one person from signing the
        // transaction multiple times.
        //
        // We need to serialize a witness transaction for each public key since the public key
        // hash is included in the serialized data.
        //
        Iterator<StackElement> it = pubKeys.iterator();
        while (it.hasNext()) {
            StackElement pubKey = it.next();
            ECKey ecKey = new ECKey(pubKey.getBytes());
            try {
                if (witnessInput) {
                    outBuffer.rewind();
                    byte[] witnessProgram = Script.getWitnessProgram(ecKey.getPubKeyHash(), true);
                    tx.serializeForSignature(txInput.getIndex(), hashType, witnessProgram, outBuffer);
                    txData = outBuffer.toByteArray();
                }
                isValid = ecKey.verifySignature(txData, encodedSig);
            } catch (ECException exc) {
                it.remove();
            }
            //
            // Remove the public key from the list if the verification is successful
            //
            if (isValid) {
                it.remove();
                break;
            }
        }
        return isValid;
    }
}
