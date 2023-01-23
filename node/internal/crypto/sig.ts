// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

import { Buffer } from "../../buffer.ts";
import type { WritableOptions } from "../../_stream.d.ts";
import {
  ERR_CRYPTO_SIGN_KEY_REQUIRED,
  ERR_INVALID_ARG_TYPE,
  ERR_INVALID_ARG_VALUE,
} from "../errors.ts";
import { ObjectSetPrototypeOf, ReflectApply } from "../primordials.mjs";
import Writable from "../streams/writable.mjs";
import { isArrayBufferView } from "../util/types.ts";
import { validateEncoding, validateString } from "../validators.mjs";
import {
  BinaryLike,
  CreatePrivateKeyParams,
  CreatePublicKeyParams,
  KeyObject,
  ObjectPrivateKeyParams,
  ObjectPublicKeyParams,
  preparePrivateKey,
  preparePublicOrPrivateKey,
} from "./keys.ts";
import type {
  BinaryToTextEncoding,
  Encoding,
  SigningOptions,
} from "./types.ts";
import { getArrayBufferOrView, getDefaultEncoding, kHandle } from "./util.ts";
import { _Sign, _Verify, DSASigEnc } from "./_sig.ts";

export type SignOptions =
  | CreatePrivateKeyParams
  | (ObjectPrivateKeyParams | { key: KeyObject })
    & SigningOptions;

export interface Sign extends WritableStream {
  sign(
    options: SignOptions,
    outputFormat?: BinaryToTextEncoding | "buffer",
  ): Buffer | string;

  update(data: BinaryLike, encoding?: Encoding | "buffer"): this;
}

interface InternalSign extends Sign {
  [kHandle]: _Sign;
}

export const Sign = function (
  this: InternalSign | undefined,
  algorithm: string,
  options?: WritableOptions,
): Sign | void {
  if (!(this instanceof Sign)) {
    return new Sign(algorithm, options);
  }
  validateString(algorithm, "algorithm");
  this[kHandle] = new _Sign();
  this[kHandle].init(algorithm);

  ReflectApply(Writable, this, [options]);
} as {
  new (algorithm: string, options?: WritableOptions): Sign;
  (algorithm: string, options?: WritableOptions): Sign;
};

ObjectSetPrototypeOf(Sign.prototype, Writable.prototype);
ObjectSetPrototypeOf(Sign, Writable);

Sign.prototype._write = function _write(
  this: InternalSign,
  chunk: BinaryLike,
  encoding: Encoding,
  callback: () => void,
): void {
  this.update(chunk, encoding);
  callback();
};

Sign.prototype.update = function update(
  this: InternalSign,
  data: BinaryLike,
  encoding?: Encoding | "buffer",
): Sign {
  encoding = encoding || getDefaultEncoding();

  if (typeof data === "string") {
    validateEncoding(data, encoding);
  } else if (!isArrayBufferView(data)) {
    throw new ERR_INVALID_ARG_TYPE(
      "data",
      ["string", "Buffer", "TypedArray", "DataView"],
      data,
    );
  }

  this[kHandle].update(data, encoding);
  return this;
};

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

Sign.prototype.sign = function sign(
  this: InternalSign,
  options: SignOptions,
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
};

export function signOneShot(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: SignOptions,
): Buffer;
export function signOneShot(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: SignOptions,
  callback: (error: Error | null, data: Buffer) => void,
): void;
export function signOneShot(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: SignOptions,
  callback?: (error: Error | null, data: Buffer) => void,
): void | Buffer {
  const sign = new Sign(algorithm as string);
  sign.update(data);
  // TODO: If the callback function is provided this function should use libuv's threadpool.
  const signature = Buffer.from(sign.sign(key));
  if (callback) {
    callback(null, signature);
  } else {
    return signature;
  }
}

export type VerifyOptions =
  | CreatePublicKeyParams
  | (ObjectPublicKeyParams | { key: KeyObject })
    & SigningOptions;

export interface Verify extends WritableStream {
  update(data: BinaryLike, encoding?: Encoding | "buffer"): this;

  verify(
    options: VerifyOptions,
    signature: BinaryLike,
    sigEncoding?: BinaryToTextEncoding | "buffer",
  ): boolean;
}

interface InternalVerify extends Verify {
  [kHandle]: _Verify;
}

export const Verify = function (
  this: InternalVerify | undefined,
  algorithm: string,
  options?: WritableOptions,
): Verify | void {
  if (!(this instanceof Verify)) {
    return new Verify(algorithm, options);
  }
  validateString(algorithm, "algorithm");
  this[kHandle] = new _Verify();
  this[kHandle].init(algorithm);

  ReflectApply(Writable, this, [options]);
} as {
  new (algorithm: string, options?: WritableOptions): Verify;
  (algorithm: string, options?: WritableOptions): Verify;
};

ObjectSetPrototypeOf(Verify.prototype, Writable.prototype);
ObjectSetPrototypeOf(Verify, Writable);

Verify.prototype._write = Sign.prototype._write;
Verify.prototype.update = Sign.prototype.update;

Verify.prototype.verify = function verify(
  options: VerifyOptions,
  signature: ArrayBufferView | string,
  sigEncoding?: BinaryToTextEncoding | "buffer",
): boolean {
  const {
    data,
    format,
    type,
    passphrase,
  } = preparePublicOrPrivateKey(options);

  sigEncoding = sigEncoding || getDefaultEncoding();

  // Options specific to RSA
  const rsaPadding = getPadding(options);
  const pssSaltLength = getSaltLength(options);

  // Options specific to (EC)DSA
  const dsaSigEnc = getDSASignatureEncoding(options);

  signature = getArrayBufferOrView(signature, "signature", sigEncoding);

  return this[kHandle].verify(
    data,
    format,
    type,
    passphrase,
    signature,
    rsaPadding,
    pssSaltLength,
    dsaSigEnc,
  );
};

export function verifyOneShot(
  algorithm: string | null | undefined,
  data: ArrayBufferView,
  key: VerifyOptions,
  signature: ArrayBufferView,
  callback?: (error: Error | null, result: boolean) => void,
): boolean | void {
  const verify = new Verify(algorithm as string);
  verify.update(data);
  // TODO: If the callback function is provided this function should use libuv's threadpool.
  const result = verify.verify(key, signature);
  if (callback) {
    callback(null, result);
  } else {
    return result;
  }
}

export default {
  signOneShot,
  verifyOneShot,
  Sign,
  Verify,
};
