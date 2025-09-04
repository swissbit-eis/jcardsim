package com.licel.jcardsim.crypto;

import javacard.security.DESKey;
import javacard.security.KeyBuilder;

public class DESKeyImpl extends SymmetricKeyImpl implements DESKey {
    /**
     * Create new instance of <code>SymmetricKeyImpl</code>
     *
     * @param keyType keyType interface
     * @param keySize keySize in bits
     * @see KeyBuilder
     */
    public DESKeyImpl(byte keyType, short keySize) {
        super(keyType, keySize);
    }
}
