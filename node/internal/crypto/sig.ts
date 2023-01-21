// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

import { Buffer } from "../../buffer.ts";
import type { WritableOptions } from "../../_stream.d.ts";
import { notImplemented } from "../../_utils.ts";
import { ERR_CRYPTO_SIGN_KEY_REQUIRED } from "../errors.ts";
import Writable from "../streams/writable.mjs";
import { validateString } from "../validators.mjs";
import type {
  BinaryLike,
  BinaryToTextEncoding,
  Encoding,
  SigningOptions,
  SignPrivateKeyInput,
  VerifyPublicKeyInput,
} from "./types.ts";
import { getDefaultEncoding } from "./util.ts";
import { KeyLike, KeyObject, preparePrivateKey } from "./_keys.ts";

export interface SignKeyObjectInput extends SigningOptions {
  key: KeyObject;
}
export interface VerifyKeyObjectInput extends SigningOptions {
  key: KeyObject;
}

export class Sign extends Writable {
  constructor(algorithm: string, _options?: WritableOptions) {
    validateString(algorithm, "algorithm");

    super();

    notImplemented("crypto.Sign");
  }

  sign(privateKey: KeyLike | SignKeyObjectInput | SignPrivateKeyInput): Buffer;
  sign(
    privateKey: KeyLike | SignKeyObjectInput | SignPrivateKeyInput,
    outputFormat: BinaryToTextEncoding | "buffer",
  ): string;
  sign(
    privateKey: KeyLike | SignKeyObjectInput | SignPrivateKeyInput,
    outputFormat?: BinaryToTextEncoding | "buffer",
  ): Buffer | string {
    if (!privateKey) throw new ERR_CRYPTO_SIGN_KEY_REQUIRED();

    const { data, format, type, passphrase } = preparePrivateKey(privateKey);

    // Options specific to RSA
    const rsaPadding = getPadding(options);
    const pssSaltLength = getSaltLength(options);

    // Options specific to (EC)DSA
    const dsaSigEnc = getDSASignatureEncoding(options);

    const ret = this[kHandle].sign(
      data,
      format,
      type,
      passphrase,
      rsaPadding,
      pssSaltLength,
      dsaSigEnc,
    );

    outputFormat = outputFormat || getDefaultEncoding();
    if (outputFormat && outputFormat !== "buffer") {
      return ret.toString(outputFormat);
    }

    return ret;
  }

  update(data: BinaryLike): this;
  update(data: string, inputEncoding: Encoding): this;
  update(_data: BinaryLike | string, _inputEncoding?: Encoding): this {
    notImplemented("crypto.Sign.prototype.update");
  }
}

export class Verify extends Writable {
  constructor(algorithm: string, _options?: WritableOptions) {
    validateString(algorithm, "algorithm");

    super();

    notImplemented("crypto.Verify");
  }

  update(data: BinaryLike): this;
  update(data: string, inputEncoding: Encoding): this;
  update(_data: BinaryLike, _inputEncoding?: string): this {
    notImplemented("crypto.Sign.prototype.update");
  }

  verify(
    object: KeyLike | VerifyKeyObjectInput | VerifyPublicKeyInput,
    signature: ArrayBufferView,
  ): boolean;
  verify(
    object: KeyLike | VerifyKeyObjectInput | VerifyPublicKeyInput,
    signature: string,
    signatureEncoding?: BinaryToTextEncoding,
  ): boolean;
  verify(
    _object: KeyLike | VerifyKeyObjectInput | VerifyPublicKeyInput,
    _signature: ArrayBufferView | string,
    _signatureEncoding?: BinaryToTextEncoding,
  ): boolean {
    notImplemented("crypto.Sign.prototype.sign");
  }
}

export function signOneShot(
  algorithm: string | null | undefined,
  data: ArrayBufferView,
  key: KeyLike | SignKeyObjectInput | SignPrivateKeyInput,
): Buffer;
export function signOneShot(
  algorithm: string | null | undefined,
  data: ArrayBufferView,
  key: KeyLike | SignKeyObjectInput | SignPrivateKeyInput,
  callback: (error: Error | null, data: Buffer) => void,
): void;
export function signOneShot(
  _algorithm: string | null | undefined,
  _data: ArrayBufferView,
  _key: KeyLike | SignKeyObjectInput | SignPrivateKeyInput,
  _callback?: (error: Error | null, data: Buffer) => void,
): Buffer | void {
  notImplemented("crypto.sign");
}

export function verifyOneShot(
  algorithm: string | null | undefined,
  data: ArrayBufferView,
  key: KeyLike | VerifyKeyObjectInput | VerifyPublicKeyInput,
  signature: ArrayBufferView,
): boolean;
export function verifyOneShot(
  algorithm: string | null | undefined,
  data: ArrayBufferView,
  key: KeyLike | VerifyKeyObjectInput | VerifyPublicKeyInput,
  signature: ArrayBufferView,
  callback: (error: Error | null, result: boolean) => void,
): void;
export function verifyOneShot(
  _algorithm: string | null | undefined,
  _data: ArrayBufferView,
  _key: KeyLike | VerifyKeyObjectInput | VerifyPublicKeyInput,
  _signature: ArrayBufferView,
  _callback?: (error: Error | null, result: boolean) => void,
): boolean | void {
  notImplemented("crypto.verify");
}

export default {
  signOneShot,
  verifyOneShot,
  Sign,
  Verify,
};
