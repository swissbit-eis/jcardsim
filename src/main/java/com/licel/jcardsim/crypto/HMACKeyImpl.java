package com.licel.jcardsim.crypto;

import javacard.security.HMACKey;
import javacard.security.KeyBuilder;

public class HMACKeyImpl extends SymmetricKeyImpl implements HMACKey {
    /**
     * Create new instance of <code>SymmetricKeyImpl</code>
     *
     * @param keyType keyType interface
     * @param keySize keySize in bits
     * @see KeyBuilder
     */
    public HMACKeyImpl(byte keyType, short keySize) {
        super(keyType, keySize);
    }
}
