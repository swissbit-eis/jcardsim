package com.licel.jcardsim.crypto;

import javacard.security.KeyBuilder;
import javacard.security.KoreanSEEDKey;

public class KoreanSEEDKeyImpl extends SymmetricKeyImpl implements KoreanSEEDKey {

    /**
     * Create new instance of <code>SymmetricKeyImpl</code>
     *
     * @param keyType keyType interface
     * @param keySize keySize in bits
     * @see KeyBuilder
     */
    public KoreanSEEDKeyImpl(byte keyType, short keySize) {
        super(keyType, keySize);
    }
}
