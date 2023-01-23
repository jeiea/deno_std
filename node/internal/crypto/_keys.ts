// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
import { Buffer } from "../../buffer.ts";
import { notImplemented } from "../../_utils.ts";
import { BinaryLike, KeyType } from "./types.ts";
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
    keyType: KeyTypeOrdinal,
    data: BinaryLike | KeyObjectHandle,
    format?: PKFormatType,
    type?: PKEncodingType,
    passphrase?: string | Buffer,
  ) {
  }

  initEDRaw(crv: string, keyData: Buffer, keyType: KeyTypeOrdinal): boolean {
    notImplemented(this.initEDRaw.name);
  }

  initJwk(jwk: JsonWebKey, crv?: string) {
    notImplemented(this.initJwk.name);
  }

  keyDetail(detail: unknown): {} {
    notImplemented(this.keyDetail.name);
  }

  getSymmetricKeySize(): number {
    notImplemented(this.getSymmetricKeySize.name);
  }

  getAsymmetricKeyType(): KeyType {
    notImplemented(this.getAsymmetricKeyType.name);
  }

  export(
    format?: PKFormatType,
    type?: PKEncodingType,
    cipher?: string,
    passphrase?: string | Buffer,
  ): void {
    notImplemented(this.export.name);
  }

  exportJwk(options: unknown, bool: boolean) {
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
