package com.licel.jcardsim.crypto;

import javacard.security.AESKey;
import javacard.security.KeyBuilder;

public class AESKeyImpl extends SymmetricKeyImpl implements AESKey {

  /**
   * Create new instance of <code>SymmetricKeyImpl</code>
   *
   * @param keyType keyType interface
   * @param keySize keySize in bits
   * @see KeyBuilder
   */
  public AESKeyImpl(byte keyType, short keySize) {
    super(keyType, keySize);
  }
}
