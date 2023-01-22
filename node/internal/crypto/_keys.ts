// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
import { Buffer } from "../../buffer.ts";
import { notImplemented } from "../../_utils.ts";
import { KeyType } from "./types.ts";
import { kHandle } from "./util.ts";

export enum PKEncodingType {
  // RSAPublicKey / RSAPrivateKey according to PKCS#1.
  kKeyEncodingPKCS1,
  // PrivateKeyInfo or EncryptedPrivateKeyInfo according to PKCS#8.
  kKeyEncodingPKCS8,
  // SubjectPublicKeyInfo according to X.509.
  kKeyEncodingSPKI,
  // ECPrivateKey according to SEC1.
  kKeyEncodingSEC1,
}

export enum PKFormatType {
  kKeyFormatDER,
  kKeyFormatPEM,
  kKeyFormatJWK,
}

export enum KeyTypeOrdinal {
  kKeyTypeSecret,
  kKeyTypePublic,
  kKeyTypePrivate,
}

export class KeyObjectHandle {
  init(
    kKeyTypePrivate,
    data,
    format?: unknown,
    type?: unknown,
    passphrase?: unknown,
  ) {
  }

  initJwk(jwk, crv?: unknown) {
    notImplemented(this.initJwk.name);
  }

  initEDRaw(crv, keyData, keyType): boolean {
    notImplemented(this.initEDRaw.name);
  }

  getSymmetricKeySize(): number {
    notImplemented(this.getSymmetricKeySize.name);
  }

  getAsymmetricKeyType(): KeyType {
    notImplemented(this.getAsymmetricKeyType.name);
  }

  keyDetail(detail): {} {
    notImplemented(this.keyDetail.name);
  }

  export(
    format?: PKFormatType,
    type?: PKEncodingType,
    cipher?: string,
    passphrase?: string | Buffer,
  ): void {
    notImplemented(this.export.name);
  }

  exportJwk(options, bool: boolean) {
    notImplemented(this.exportJwk.name);
  }

  equals(otherHandle: KeyObjectHandle): boolean {
    return this === otherHandle;
  }
}

export class NativeKeyObject {
  [kHandle]: KeyObjectHandle;

  constructor(handle: KeyObjectHandle) {
    this[kHandle] = handle;
  }
}
