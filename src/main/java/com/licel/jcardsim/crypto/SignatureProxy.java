/*
 * Copyright 2015 Licel Corporation.
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
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * ProxyClass for <code>Signature</code>
 * @see Signature
 */
public class SignatureProxy {
    /**
     * Creates a <code>Signature</code> object instance of the selected algorithm.
     * @param algorithm the desired Signature algorithm. Valid codes listed in
     * ALG_ .. constants above e.g. <A HREF="../../javacard/security/Signature.html#ALG_DES_MAC4_NOPAD"><CODE>ALG_DES_MAC4_NOPAD</CODE></A>
     * @param externalAccess <code>true</code> indicates that the instance will be shared among
     * multiple applet instances and that the <code>Signature</code> instance will also be accessed (via a <code>Shareable</code>
     * interface) when the owner of the <code>Signature</code> instance is not the currently selected applet.
     * If <code>true</code> the implementation must not allocate CLEAR_ON_DESELECT transient space for internal data.
     * @return the <code>Signature</code> object instance of the requested algorithm
     * @throws CryptoException with the following reason codes:<ul>
     * <li><code>CryptoException.NO_SUCH_ALGORITHM</code> if the requested algorithm
     * or shared access mode is not supported.</ul>
     */
    public static final Signature getInstance(byte algorithm, boolean externalAccess)
            throws CryptoException {
        Signature instance = null;
        //TODO: implement externalAccess logic
//        if (externalAccess) {
//            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
//        }
        switch (algorithm) {
            case Signature.ALG_RSA_SHA_ISO9796:
            case Signature.ALG_RSA_SHA_PKCS1:
            case Signature.ALG_RSA_SHA_224_PKCS1:
            case Signature.ALG_RSA_SHA_256_PKCS1:
            case Signature.ALG_RSA_SHA_384_PKCS1:
            case Signature.ALG_RSA_SHA_512_PKCS1:
            case Signature.ALG_RSA_SHA_PKCS1_PSS:
            case Signature.ALG_RSA_SHA_224_PKCS1_PSS:
            case Signature.ALG_RSA_SHA_256_PKCS1_PSS:
            case Signature.ALG_RSA_SHA_384_PKCS1_PSS:
            case Signature.ALG_RSA_SHA_512_PKCS1_PSS:
            case Signature.ALG_RSA_MD5_PKCS1:
            case Signature.ALG_RSA_RIPEMD160_ISO9796:
            case Signature.ALG_RSA_RIPEMD160_PKCS1:
            case Signature.ALG_ECDSA_SHA:
            case Signature.ALG_ECDSA_SHA_224:
            case Signature.ALG_ECDSA_SHA_256:
            case Signature.ALG_ECDSA_SHA_384:
            case Signature.ALG_ECDSA_SHA_512:
            case Signature.ALG_RSA_SHA_ISO9796_MR:
            case Signature.ALG_DSA_SHA:
            case Signature.ALG_RSA_SHA_RFC2409:
            case Signature.ALG_RSA_MD5_RFC2409:
            case Signature.ALG_RSA_MD5_PKCS1_PSS:
            case Signature.ALG_RSA_RIPEMD160_PKCS1_PSS:
            case Signature.ALG_RSA_RIPEMD160_ISO9796_MR:
                System.out.println("getInstance of assymetric algo: " + algorithm);
                try {
                    instance = new AsymmetricSignatureImpl(algorithm);
                    System.out.println("getInstance of assymetric algo: " + algorithm + " is OK!");
                } catch(Exception e) {
                    e.printStackTrace();
                    e.getCause().printStackTrace();
                    CryptoException.throwIt(CryptoException.INVALID_INIT);
                }
                break;
            case Signature.ALG_DES_MAC4_NOPAD:
            case Signature.ALG_DES_MAC8_NOPAD:
            case Signature.ALG_DES_MAC4_ISO9797_M1:
            case Signature.ALG_DES_MAC8_ISO9797_M1:
            case Signature.ALG_DES_MAC4_ISO9797_M2:
            case Signature.ALG_DES_MAC8_ISO9797_M2:
            case Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3:
            case Signature.ALG_DES_MAC4_PKCS5:
            case Signature.ALG_DES_MAC8_PKCS5:
            case Signature.ALG_AES_MAC_128_NOPAD:
            case Signature.ALG_HMAC_SHA1:                
            case Signature.ALG_HMAC_SHA_256:                
            case Signature.ALG_HMAC_SHA_384:                
            case Signature.ALG_HMAC_SHA_512:                
            case Signature.ALG_HMAC_MD5:                
            case Signature.ALG_HMAC_RIPEMD160:
            case Signature.ALG_AES_CMAC_128:
                instance = new SymmetricSignatureImpl(algorithm);
                break;

            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;


        }
        return instance;
    }

  private static byte getSignatureAlgorithm(
      byte messageDigestAlgorithm, byte cipherAlgorithm, byte paddingAlgorithm) {
    if (paddingAlgorithm != Cipher.PAD_NULL) {
      throw new UnsupportedOperationException();
    }
    switch (cipherAlgorithm) {
      case Signature.SIG_CIPHER_HMAC:
        switch (messageDigestAlgorithm) {
          case MessageDigest.ALG_SHA:
            return Signature.ALG_HMAC_SHA1;
          case MessageDigest.ALG_SHA_256:
            return Signature.ALG_HMAC_SHA_256;
          case MessageDigest.ALG_SHA_384:
            return Signature.ALG_HMAC_SHA_384;
          case MessageDigest.ALG_SHA_512:
            return Signature.ALG_HMAC_SHA_512;
        }
        break;
      case Signature.SIG_CIPHER_ECDSA:
        switch (messageDigestAlgorithm) {
          case MessageDigest.ALG_SHA_256:
            return Signature.ALG_ECDSA_SHA_256;
          case MessageDigest.ALG_SHA_384:
            return Signature.ALG_ECDSA_SHA_384;
          case MessageDigest.ALG_SHA_512:
            return Signature.ALG_ECDSA_SHA_512;
        }
        break;
    }
    throw new UnsupportedOperationException();
  }

  public static Signature getInstance(
      byte messageDigestAlgorithm,
      byte cipherAlgorithm,
      byte paddingAlgorithm,
      boolean externalAccess)
      throws CryptoException {
    byte signatureAlgorithm =
        getSignatureAlgorithm(messageDigestAlgorithm, cipherAlgorithm, paddingAlgorithm);
    return getInstance(signatureAlgorithm, externalAccess);
  }

  public static final class OneShotProxy extends Signature {
    public static OneShotProxy open(
        byte messageDigestAlgorithm, byte cipherAlgorithm, byte paddingAlgorithm)
        throws CryptoException {
      return new OneShotProxy(
          Signature.getInstance(messageDigestAlgorithm, cipherAlgorithm, paddingAlgorithm, false));
    }

    final Signature internalSignature;

    public OneShotProxy(Signature internalSignature) {
      this.internalSignature = internalSignature;
    }

    public void close() {
      // todo
    }

    @Override
    public void init(Key key, byte theMode) throws CryptoException {
      internalSignature.init(key, theMode);
    }

    @Override
    public void init(Key key, byte theMode, byte[] bArray, short bOff, short bLen)
        throws CryptoException {
      internalSignature.init(key, theMode, bArray, bOff, bLen);
    }

    @Override
    public void setInitialDigest(
        byte[] state,
        short stateOffset,
        short stateLength,
        byte[] digestedMsgLenBuf,
        short digestedMsgLenOffset,
        short digestedMsgLenLength)
        throws CryptoException {
      internalSignature.setInitialDigest(
          state,
          stateOffset,
          stateLength,
          digestedMsgLenBuf,
          digestedMsgLenOffset,
          digestedMsgLenLength);
    }

    @Override
    public byte getAlgorithm() {
      return internalSignature.getAlgorithm();
    }

    @Override
    public byte getMessageDigestAlgorithm() {
      return internalSignature.getMessageDigestAlgorithm();
    }

    @Override
    public byte getCipherAlgorithm() {
      return internalSignature.getCipherAlgorithm();
    }

    @Override
    public byte getPaddingAlgorithm() {
      return internalSignature.getPaddingAlgorithm();
    }

    @Override
    public short getLength() throws CryptoException {
      return internalSignature.getLength();
    }

    @Override
    public void update(byte[] bytes, short i, short i1) throws CryptoException {
      throw new CryptoException(CryptoException.ILLEGAL_USE);
    }

    @Override
    public short sign(
        byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset)
        throws CryptoException {
      return internalSignature.sign(inBuff, inOffset, inLength, sigBuff, sigOffset);
    }

    @Override
    public short signPreComputedHash(
        byte[] hashBuff, short hashOff, short hashLength, byte[] sigBuff, short sigOffset)
        throws CryptoException {
      return internalSignature.signPreComputedHash(
          hashBuff, hashOff, hashLength, sigBuff, sigOffset);
    }

    @Override
    public boolean verify(
        byte[] inBuff,
        short inOffset,
        short inLength,
        byte[] sigBuff,
        short sigOffset,
        short sigLength)
        throws CryptoException {
      return internalSignature.verify(inBuff, inOffset, inLength, sigBuff, sigOffset, sigLength);
    }

    @Override
    public boolean verifyPreComputedHash(
        byte[] hashBuff,
        short hashOff,
        short hashLength,
        byte[] sigBuff,
        short sigOffset,
        short sigLength)
        throws CryptoException {
      return internalSignature.verifyPreComputedHash(
          hashBuff, hashOff, hashLength, sigBuff, sigOffset, sigLength);
    }
  }
}
