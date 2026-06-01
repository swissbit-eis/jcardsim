package com.licel.jcardsim.base;

import javacard.framework.Util;

public class ElfVersion {
  final byte major;
  final byte minor;

  public ElfVersion(byte major, byte minor) {
    this.major = major;
    this.minor = minor;
  }

  public byte[] toBytes() {
    return new byte[] {major, minor};
  }

  public short toShort() {
    return Util.getShort(toBytes(), (short) 0);
  }

  @Override
  public String toString() {
    return "v"+major+"."+minor;
  }
}
