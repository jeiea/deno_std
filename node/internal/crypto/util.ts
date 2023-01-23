// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

import { Buffer } from "../../buffer.ts";
import { crypto as constants } from "../../internal_binding/constants.ts";
import { getCiphers } from "../../_crypto/crypto_browserify/browserify_aes/mod.js";
import { notImplemented } from "../../_utils.ts";
import { ERR_INVALID_ARG_TYPE, hideStackFrames } from "../errors.ts";
import { isAnyArrayBuffer, isArrayBufferView } from "../util/types.ts";
import { kHandle, kKeyObject } from "./constants.ts";
import { BinaryToTextEncoding, Encoding } from "./types.ts";

// TODO(kt3k): Generate this list from `digestAlgorithms`
// of std/crypto/_wasm/mod.ts
const digestAlgorithms = [
  "blake2b256",
  "blake2b384",
  "blake2b",
  "blake2s",
  "blake3",
  "keccak-224",
  "keccak-256",
  "keccak-384",
  "keccak-512",
  "sha384",
  "sha3-224",
  "sha3-256",
  "sha3-384",
  "sha3-512",
  "shake128",
  "shake256",
  "tiger",
  "rmd160",
  "sha224",
  "sha256",
  "sha512",
  "md4",
  "md5",
  "sha1",
];

let defaultEncoding: BinaryToTextEncoding | "buffer" = "buffer";

export function setDefaultEncoding(val: BinaryToTextEncoding | "buffer") {
  defaultEncoding = val;
}

export function getDefaultEncoding(): BinaryToTextEncoding | "buffer" {
  return defaultEncoding;
}

// This is here because many functions accepted binary strings without
// any explicit encoding in older versions of node, and we don't want
// to break them unnecessarily.
export function toBuf(val: string | Buffer, encoding?: string): Buffer {
  if (typeof val === "string") {
    if (encoding === "buffer") {
      encoding = "utf8";
    }

    return Buffer.from(val, encoding);
  }

  return val;
}

export const validateByteSource = hideStackFrames((val, name) => {
  val = toBuf(val);

  if (isAnyArrayBuffer(val) || isArrayBufferView(val)) {
    return;
  }

  throw new ERR_INVALID_ARG_TYPE(
    name,
    ["string", "ArrayBuffer", "TypedArray", "DataView", "Buffer"],
    val,
  );
});

/**
 * Returns an array of the names of the supported hash algorithms, such as 'sha1'.
 */
export function getHashes(): readonly string[] {
  return digestAlgorithms;
}

export function getCurves(): readonly string[] {
  notImplemented("crypto.getCurves");
}

export interface SecureHeapUsage {
  total: number;
  min: number;
  used: number;
  utilization: number;
}

export function secureHeapUsed(): SecureHeapUsage {
  notImplemented("crypto.secureHeapUsed");
}

export function setEngine(_engine: string, _flags: typeof constants) {
  notImplemented("crypto.setEngine");
}

export const getArrayBufferOrView = hideStackFrames(
  <T extends string | Buffer | ArrayBufferLike | ArrayBufferView>(
    buffer: T,
    name: string,
    encoding?: Encoding | "buffer",
  ) => {
    if (isAnyArrayBuffer(buffer)) {
      return buffer;
    }
    if (typeof buffer === "string") {
      if (encoding === "buffer") {
        encoding = "utf8";
      }
      return Buffer.from(buffer, encoding);
    }
    if (!isArrayBufferView(buffer)) {
      throw new ERR_INVALID_ARG_TYPE(
        name,
        [
          "string",
          "ArrayBuffer",
          "Buffer",
          "TypedArray",
          "DataView",
        ],
        buffer,
      );
    }
    return buffer;
  },
);

export function bigIntArrayToUnsignedBigInt(input: Uint8Array): bigint {
  let result = 0n;

  for (let n = 0; n < input.length; ++n) {
    const n_reversed = input.length - n - 1;
    result |= BigInt(input[n]) << 8n * BigInt(n_reversed);
  }

  return result;
}

export { getCiphers, kHandle, kKeyObject };

export default {
  bigIntArrayToUnsignedBigInt,
  getArrayBufferOrView,
  getDefaultEncoding,
  getHashes,
  setDefaultEncoding,
  getCiphers,
  getCurves,
  secureHeapUsed,
  setEngine,
  validateByteSource,
  toBuf,
  kHandle,
  kKeyObject,
};
