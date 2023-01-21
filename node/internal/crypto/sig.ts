// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

import { Buffer } from "../../buffer.ts";
import type { WritableOptions } from "../../_stream.d.ts";
import { notImplemented } from "../../_utils.ts";
import {
  ERR_CRYPTO_SIGN_KEY_REQUIRED,
  ERR_INVALID_ARG_VALUE,
} from "../errors.ts";
import Writable from "../streams/writable.mjs";
import { validateString } from "../validators.mjs";
import {
  CreatePrivateKeyParams,
  KeyLike,
  KeyObject,
  preparePrivateKey,
} from "./keys.ts";
import type {
  BinaryLike,
  BinaryToTextEncoding,
  Encoding,
  SigningOptions,
  VerifyPublicKeyInput,
} from "./types.ts";
import { getDefaultEncoding, kHandle } from "./util.ts";
import { _Sign } from "./_sig.ts";

enum DSASigEnc {
  kSigEncDER,
  kSigEncP1363,
}
export interface SignKeyObjectInput extends SigningOptions {
  key: KeyObject;
}
export interface VerifyKeyObjectInput extends SigningOptions {
  key: KeyObject;
}

type SignPrivateKeyInput = CreatePrivateKeyParams & SigningOptions;

export class Sign extends Writable {
  private [kHandle]: _Sign;

  constructor(algorithm: string, options?: WritableOptions) {
    validateString(algorithm, "algorithm");

    super(options);

    this[kHandle] = new _Sign();
    this[kHandle].init(algorithm);
  }

  sign(options: KeyLike | SignPrivateKeyInput): Buffer;
  sign(
    options: KeyLike | SignPrivateKeyInput,
    outputFormat: BinaryToTextEncoding | "buffer",
  ): string;
  sign(
    options: KeyLike | SignPrivateKeyInput,
    outputFormat?: BinaryToTextEncoding | "buffer",
  ): Buffer | string {
    if (!options) throw new ERR_CRYPTO_SIGN_KEY_REQUIRED();

    const { data, format, type, passphrase } = preparePrivateKey(options);

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

function getPadding(options: unknown): number | undefined {
  return getIntOption("padding", options);
}

function getSaltLength(options: unknown): number | undefined {
  return getIntOption("saltLength", options);
}

function getDSASignatureEncoding(options: unknown): DSASigEnc {
  if (typeof options === "object") {
    const { dsaEncoding = "der" } = options as { dsaEncoding?: string };
    if (dsaEncoding === "der") {
      return DSASigEnc.kSigEncDER;
    } else if (dsaEncoding === "ieee-p1363") {
      return DSASigEnc.kSigEncP1363;
    }
    throw new ERR_INVALID_ARG_VALUE("options.dsaEncoding", dsaEncoding);
  }

  return DSASigEnc.kSigEncDER;
}

function getIntOption(name: string, options: unknown): number | undefined {
  const value = (options as Record<string, unknown>)[name];
  if (value !== undefined) {
    if (value === (value as number) >> 0) {
      return value;
    }
    throw new ERR_INVALID_ARG_VALUE(`options.${name}`, value);
  }
  return undefined;
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
