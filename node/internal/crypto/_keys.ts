// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
import { Buffer } from "../../buffer.ts";
import { notImplemented } from "../../_utils.ts";
import {
  ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS,
  ERR_CRYPTO_INVALID_JWK,
  ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE,
  ERR_ILLEGAL_CONSTRUCTOR,
  ERR_INVALID_ARG_TYPE,
  ERR_INVALID_ARG_VALUE,
  ERR_INVALID_THIS,
} from "../errors.ts";
import {
  ArrayFrom,
  ArrayPrototypeSlice,
  ObjectDefineProperties,
  ObjectDefineProperty,
} from "../primordials.mjs";
import {
  customInspectSymbol as kInspect,
  kEnumerableProperty,
} from "../util.mjs";
import { inspect } from "../util/inspect.mjs";
import { isAnyArrayBuffer, isArrayBufferView } from "../util/types.ts";
import {
  validateObject,
  validateOneOf,
  validateString,
} from "../validators.mjs";
import {
  Encoding,
  KeyType,
  PrivateKeyInput,
  SignPrivateKeyInput,
} from "./types.ts";
import { getArrayBufferOrView, kHandle, kKeyObject } from "./util.ts";

const {
  kKeyTypeSecret,
  kKeyTypePublic,
  kKeyTypePrivate,
  kKeyFormatPEM,
  kKeyFormatDER,
  kKeyFormatJWK,
} = internalBinding("crypto");

enum PKEncodingType {
  // RSAPublicKey / RSAPrivateKey according to PKCS#1.
  kKeyEncodingPKCS1,
  // PrivateKeyInfo or EncryptedPrivateKeyInfo according to PKCS#8.
  kKeyEncodingPKCS8,
  // SubjectPublicKeyInfo according to X.509.
  kKeyEncodingSPKI,
  // ECPrivateKey according to SEC1.
  kKeyEncodingSEC1,
}

// const {
//   validateObject,
//   validateOneOf,
//   validateString,
// } = require('internal/validators');

// const {
//   codes: {
//     ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS,
//     ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE,
//     ERR_CRYPTO_INVALID_JWK,
//     ERR_ILLEGAL_CONSTRUCTOR,
//     ERR_INVALID_ARG_TYPE,
//     ERR_INVALID_ARG_VALUE,
//     ERR_INVALID_THIS,
//   }
// } = require('internal/errors');

// const {
//   isAnyArrayBuffer,
//   isArrayBufferView,
// } = require('internal/util/types');

// const {
//   makeTransferable,
//   kClone,
//   kDeserialize,
// } = require('internal/worker/js_transferable');

// const {
//   customInspectSymbol: kInspect,
//   kEnumerableProperty,
// } = require('internal/util');

// const { inspect } = require('internal/util/inspect');

// const { Buffer } = require('buffer');

const kAlgorithm = Symbol("kAlgorithm");
const kExtractable = Symbol("kExtractable");
const kKeyType = Symbol("kKeyType");
const kKeyUsages = Symbol("kKeyUsages");

type KeyInputContext = 0 | 1 | 2 | 3;
const kConsumePublic = 0;
const kConsumePrivate = 1;
const kCreatePublic = 2;
const kCreatePrivate = 3;

type PKEncodingName = "pkcs1" | "pkcs8" | "spki" | "sec1";
const encodingNames: string[] = [];
for (
  const [ordinal, name] of [
    [PKEncodingType.kKeyEncodingPKCS1, "pkcs1"],
    [PKEncodingType.kKeyEncodingPKCS8, "pkcs8"],
    [PKEncodingType.kKeyEncodingSPKI, "spki"],
    [PKEncodingType.kKeyEncodingSEC1, "sec1"],
  ] as const
) {
  encodingNames[ordinal] = name;
}

type KeyObjectType = "secret" | "private" | "public";

class KeyObjectHandle {
  init(
    kKeyTypePrivate,
    data,
    format?: unknown,
    type?: unknown,
    passphrase?: unknown,
  ) {
  }

  initJwk(jwk, crv?: unknown) {
  }

  initEDRaw(crv, keyData, keyType): boolean {
    return true;
  }

  getSymmetricKeySize(): number {
    notImplemented(this.getSymmetricKeySize.name);
  }

  export(): void;
  export(format, type): void;
  export(format, type, cipher: string, passphrase: string | Buffer): void;
  export(format, type, cipher?: string, passphrase?: string | Buffer): void {}

  exportJwk(options, bool: boolean) {}

  equals(otherHandle: KeyObjectHandle): boolean {
    return this === otherHandle;
  }
}

class NativeKeyObject {
  [kHandle]: KeyObjectHandle;

  constructor(handle: KeyObjectHandle) {
    this[kHandle] = handle;
  }
}

// Publicly visible KeyObject class.
export class KeyObject extends NativeKeyObject {
  private [kKeyType]: KeyObjectType;

  constructor(type: KeyObjectType, handle: KeyObjectHandle) {
    if (type !== "secret" && type !== "public" && type !== "private") {
      throw new ERR_INVALID_ARG_VALUE("type", type);
    }
    if (typeof handle !== "object" || !(handle instanceof KeyObjectHandle)) {
      throw new ERR_INVALID_ARG_TYPE("handle", "object", handle);
    }

    super(handle);

    this[kKeyType] = type;

    ObjectDefineProperty(this, kHandle, {
      __proto__: null,
      value: handle,
      enumerable: false,
      configurable: false,
      writable: false,
    } as unknown as PropertyDescriptorMap);
  }

  get type() {
    return this[kKeyType];
  }

  static from(key: CryptoKey) {
    if (!isCryptoKey(key)) {
      throw new ERR_INVALID_ARG_TYPE("key", "CryptoKey", key);
    }
    return key[kKeyObject];
  }

  equals(otherKeyObject: KeyObject) {
    if (!isKeyObject(otherKeyObject)) {
      throw new ERR_INVALID_ARG_TYPE(
        "otherKeyObject",
        "KeyObject",
        otherKeyObject,
      );
    }

    return otherKeyObject.type === this.type &&
      this[kHandle].equals(otherKeyObject[kHandle]);
  }
}

ObjectDefineProperties(KeyObject.prototype, {
  [SymbolToStringTag]: {
    __proto__: null,
    configurable: true,
    value: "KeyObject",
  } as unknown as PropertyDescriptorMap,
});

export class SecretKeyObject extends KeyObject {
  constructor(handle: KeyObjectHandle) {
    super("secret", handle);
  }

  get symmetricKeySize() {
    return this[kHandle].getSymmetricKeySize();
  }

  export(options?: { format?: "buffer" | "jwk" }) {
    if (options !== undefined) {
      validateObject(options, "options");
      validateOneOf(options.format, "options.format", [
        undefined,
        "buffer",
        "jwk",
      ]);
      if (options.format === "jwk") {
        return this[kHandle].exportJwk({}, false);
      }
    }
    return this[kHandle].export();
  }
}

const kAsymmetricKeyType = Symbol("kAsymmetricKeyType");
const kAsymmetricKeyDetails = Symbol("kAsymmetricKeyDetails");

function normalizeKeyDetails(details: {} = {}) {
  if (details.publicExponent !== undefined) {
    return {
      ...details,
      publicExponent: bigIntArrayToUnsignedBigInt(
        new Uint8Array(details.publicExponent),
      ),
    };
  }
  return details;
}

class AsymmetricKeyObject extends KeyObject {
  constructor(type: KeyObjectType, handle: KeyObjectHandle) {
    super(type, handle);
  }

  get asymmetricKeyType() {
    return (
      this[kAsymmetricKeyType] ||
      (this[kAsymmetricKeyType] = this[kHandle].getAsymmetricKeyType())
    );
  }

  get asymmetricKeyDetails() {
    switch (this.asymmetricKeyType) {
      case "rsa":
      case "rsa-pss":
      case "dsa":
      case "ec":
        return (
          this[kAsymmetricKeyDetails] ||
          (this[kAsymmetricKeyDetails] = normalizeKeyDetails(
            this[kHandle].keyDetail({}),
          ))
        );
      default:
        return {};
    }
  }
}

export class PublicKeyObject extends AsymmetricKeyObject {
  constructor(handle: KeyObjectHandle) {
    super("public", handle);
  }

  export(options: PublicKeyInput) {
    if (options && options.format as "jwk" === "jwk") {
      return this[kHandle].exportJwk({}, false);
    }
    const { format, type } = parsePublicKeyEncoding(
      options,
      this.asymmetricKeyType,
    );
    return this[kHandle].export(format, type);
  }
}

export class PrivateKeyObject extends AsymmetricKeyObject {
  constructor(handle: KeyObjectHandle) {
    super("private", handle);
  }

  export(options: PrivateKeyInput) {
    if (options && options.format as "jwk" === "jwk") {
      if (options.passphrase !== undefined) {
        throw new ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS(
          "jwk",
          "does not support encryption",
        );
      }
      return this[kHandle].exportJwk({}, false);
    }
    const { format, type, cipher, passphrase } = parsePrivateKeyEncoding(
      options,
      this.asymmetricKeyType,
    );
    return this[kHandle].export(format, type, cipher, passphrase);
  }
}

type KeyFormatString = "pem" | "der" | "jwk";

function parseKeyFormat(
  formatStr: KeyFormatString | undefined,
  defaultFormat: KeyFormatString | undefined,
  optionName: string,
) {
  if (formatStr === undefined && defaultFormat !== undefined) {
    return defaultFormat;
  } else if (formatStr === "pem") return kKeyFormatPEM;
  else if (formatStr === "der") return kKeyFormatDER;
  else if (formatStr === "jwk") return kKeyFormatJWK;
  throw new ERR_INVALID_ARG_VALUE(optionName, formatStr);
}

function parseKeyType(
  typeStr: PKEncodingName | undefined,
  required: boolean,
  keyType: KeyType | undefined,
  isPublic: boolean | undefined,
  optionName: string,
): PKEncodingType | undefined {
  if (typeStr === undefined && !required) {
    return undefined;
  } else if (typeStr === "pkcs1") {
    if (keyType !== undefined && keyType !== "rsa") {
      throw new ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS(
        typeStr,
        "can only be used for RSA keys",
      );
    }
    return PKEncodingType.kKeyEncodingPKCS1;
  } else if (typeStr === "spki" && isPublic !== false) {
    return PKEncodingType.kKeyEncodingSPKI;
  } else if (typeStr === "pkcs8" && isPublic !== true) {
    return PKEncodingType.kKeyEncodingPKCS8;
  } else if (typeStr === "sec1" && isPublic !== true) {
    if (keyType !== undefined && keyType !== "ec") {
      throw new ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS(
        typeStr,
        "can only be used for EC keys",
      );
    }
    return PKEncodingType.kKeyEncodingSEC1;
  }

  throw new ERR_INVALID_ARG_VALUE(optionName, typeStr);
}

function option(name: string, objName?: string): string {
  return objName === undefined
    ? `options.${name}`
    : `options.${objName}.${name}`;
}

function parseKeyFormatAndType(
  enc: { format?: KeyFormatString; type?: PKEncodingName },
  keyType?: KeyType,
  isPublic?: boolean,
  objName?: string,
) {
  const { format: formatStr, type: typeStr } = enc;

  const isInput = keyType === undefined;
  const format = parseKeyFormat(
    formatStr,
    isInput ? kKeyFormatPEM : undefined,
    option("format", objName),
  );

  const isRequired = (!isInput || format === kKeyFormatDER) &&
    format !== kKeyFormatJWK;
  const type = parseKeyType(
    typeStr,
    isRequired,
    keyType,
    isPublic,
    option("type", objName),
  );
  return { format, type };
}

function isStringOrBuffer(val: unknown): val is string | Buffer {
  return typeof val === "string" || isArrayBufferView(val) ||
    isAnyArrayBuffer(val);
}

export function parseKeyEncoding(
  enc: PublicKeyInput | PrivateKeyInput,
  keyType: KeyType,
  isPublic?: boolean,
  objName?: string,
) {
  validateObject(enc, "options");

  const isInput = keyType === undefined;

  const { format, type } = parseKeyFormatAndType(
    enc,
    keyType,
    isPublic,
    objName,
  );

  let cipher, passphrase, encoding;
  if (isPublic !== true) {
    ({ cipher, passphrase, encoding } = enc);

    if (!isInput) {
      if (cipher != null) {
        if (typeof cipher !== "string") {
          throw new ERR_INVALID_ARG_VALUE(option("cipher", objName), cipher);
        }
        if (
          format === kKeyFormatDER &&
          (type === PKEncodingType.kKeyEncodingPKCS1 ||
            type === PKEncodingType.kKeyEncodingSEC1)
        ) {
          throw new ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS(
            encodingNames[type],
            "does not support encryption",
          );
        }
      } else if (passphrase !== undefined) {
        throw new ERR_INVALID_ARG_VALUE(option("cipher", objName), cipher);
      }
    }

    if (
      (isInput && passphrase !== undefined && !isStringOrBuffer(passphrase)) ||
      (!isInput && cipher != null && !isStringOrBuffer(passphrase))
    ) {
      throw new ERR_INVALID_ARG_VALUE(
        option("passphrase", objName),
        passphrase,
      );
    }
  }

  if (passphrase !== undefined) {
    passphrase = getArrayBufferOrView(passphrase, "key.passphrase", encoding);
  }

  return { format, type, cipher, passphrase };
}

// Parses the public key encoding based on an object. keyType must be undefined
// when this is used to parse an input encoding and must be a valid key type if
// used to parse an output encoding.
export function parsePublicKeyEncoding(
  enc: PublicKeyInput,
  keyType: "pkcs1" | "spki",
  objName?: string,
) {
  return parseKeyEncoding(enc, keyType, keyType ? true : undefined, objName);
}

// Parses the private key encoding based on an object. keyType must be undefined
// when this is used to parse an input encoding and must be a valid key type if
// used to parse an output encoding.
export function parsePrivateKeyEncoding(
  enc: PrivateKeyInput,
  keyType: "pkcs1" | "pkcs8" | "sec1",
  objName?: string,
) {
  return parseKeyEncoding(enc, keyType, false, objName);
}

function getKeyObjectHandle(key, ctx: KeyInputContext) {
  if (ctx === kCreatePrivate) {
    throw new ERR_INVALID_ARG_TYPE(
      "key",
      ["string", "ArrayBuffer", "Buffer", "TypedArray", "DataView"],
      key,
    );
  }

  if (key.type !== "private") {
    if (ctx === kConsumePrivate || ctx === kCreatePublic) {
      throw new ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE(key.type, "private");
    }
    if (key.type !== "public") {
      throw new ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE(
        key.type,
        "private or public",
      );
    }
  }

  return key[kHandle];
}

function getKeyTypes(allowKeyObject, bufferOnly = false) {
  const types = [
    "ArrayBuffer",
    "Buffer",
    "TypedArray",
    "DataView",
    "string", // Only if bufferOnly == false
    "KeyObject", // Only if allowKeyObject == true && bufferOnly == false
    "CryptoKey", // Only if allowKeyObject == true && bufferOnly == false
  ];
  if (bufferOnly) {
    return ArrayPrototypeSlice(types, 0, 4);
  } else if (!allowKeyObject) {
    return ArrayPrototypeSlice(types, 0, 5);
  }
  return types;
}

function getKeyObjectHandleFromJwk(key, ctx) {
  validateObject(key, "key");
  validateOneOf(key.kty, "key.kty", ["RSA", "EC", "OKP"]);
  const isPublic = ctx === kConsumePublic || ctx === kCreatePublic;

  if (key.kty === "OKP") {
    validateString(key.crv, "key.crv");
    validateOneOf(key.crv, "key.crv", ["Ed25519", "Ed448", "X25519", "X448"]);
    validateString(key.x, "key.x");

    if (!isPublic) validateString(key.d, "key.d");

    let keyData;
    if (isPublic) keyData = Buffer.from(key.x, "base64");
    else keyData = Buffer.from(key.d, "base64");

    switch (key.crv) {
      case "Ed25519":
      case "X25519":
        if (keyData.byteLength !== 32) {
          throw new ERR_CRYPTO_INVALID_JWK();
        }
        break;
      case "Ed448":
        if (keyData.byteLength !== 57) {
          throw new ERR_CRYPTO_INVALID_JWK();
        }
        break;
      case "X448":
        if (keyData.byteLength !== 56) {
          throw new ERR_CRYPTO_INVALID_JWK();
        }
        break;
    }

    const handle = new KeyObjectHandle();

    const keyType = isPublic ? kKeyTypePublic : kKeyTypePrivate;
    if (!handle.initEDRaw(key.crv, keyData, keyType)) {
      throw new ERR_CRYPTO_INVALID_JWK();
    }

    return handle;
  }

  if (key.kty === "EC") {
    validateString(key.crv, "key.crv");
    validateOneOf(key.crv, "key.crv", ["P-256", "secp256k1", "P-384", "P-521"]);
    validateString(key.x, "key.x");
    validateString(key.y, "key.y");

    const jwk = {
      kty: key.kty,
      crv: key.crv,
      x: key.x,
      y: key.y,
    };

    if (!isPublic) {
      validateString(key.d, "key.d");
      jwk.d = key.d;
    }

    const handle = new KeyObjectHandle();
    const type = handle.initJwk(jwk, jwk.crv);
    if (type === undefined) throw new ERR_CRYPTO_INVALID_JWK();

    return handle;
  }

  // RSA
  validateString(key.n, "key.n");
  validateString(key.e, "key.e");

  const jwk = {
    kty: key.kty,
    n: key.n,
    e: key.e,
  };

  if (!isPublic) {
    validateString(key.d, "key.d");
    validateString(key.p, "key.p");
    validateString(key.q, "key.q");
    validateString(key.dp, "key.dp");
    validateString(key.dq, "key.dq");
    validateString(key.qi, "key.qi");
    jwk.d = key.d;
    jwk.p = key.p;
    jwk.q = key.q;
    jwk.dp = key.dp;
    jwk.dq = key.dq;
    jwk.qi = key.qi;
  }

  const handle = new KeyObjectHandle();
  const type = handle.initJwk(jwk);
  if (type === undefined) throw new ERR_CRYPTO_INVALID_JWK();

  return handle;
}

function prepareAsymmetricKey(
  key: KeyLike | PrivateKeyParams,
  ctx: KeyInputContext,
) {
  // TODO (jeiea): types
  if (isKeyObject(key)) {
    // Best case: A key object, as simple as that.
    return { data: getKeyObjectHandle(key, ctx) };
  } else if (isCryptoKey(key)) {
    return { data: getKeyObjectHandle(key[kKeyObject], ctx) };
  } else if (isStringOrBuffer(key)) {
    // Expect PEM by default, mostly for backward compatibility.
    return { format: kKeyFormatPEM, data: getArrayBufferOrView(key, "key") };
  } else if (typeof key === "object") {
    const { key: data, encoding, format } = key as PrivateKeyParams;

    // The 'key' property can be a KeyObject as well to allow specifying
    // additional options such as padding along with the key.
    if (isKeyObject(data)) return { data: getKeyObjectHandle(data, ctx) };
    else if (isCryptoKey(data)) {
      return { data: getKeyObjectHandle(data[kKeyObject], ctx) };
    } else if (format === "jwk") {
      validateObject(data, "key.key");
      return { data: getKeyObjectHandleFromJwk(data, ctx), format: "jwk" };
    }

    // Either PEM or DER using PKCS#1 or SPKI.
    if (!isStringOrBuffer(data)) {
      throw new ERR_INVALID_ARG_TYPE(
        "key.key",
        getKeyTypes(ctx !== kCreatePrivate),
        data,
      );
    }

    const isPublic = ctx === kConsumePrivate || ctx === kCreatePrivate
      ? false
      : undefined;
    return {
      data: getArrayBufferOrView(data, "key", encoding),
      ...parseKeyEncoding(key, undefined, isPublic),
    };
  }
  throw new ERR_INVALID_ARG_TYPE(
    "key",
    getKeyTypes(ctx !== kCreatePrivate),
    key,
  );
}

export function preparePrivateKey(
  key: KeyLike | SignKeyObjectInput | SignPrivateKeyInput,
) {
  return prepareAsymmetricKey(key, kConsumePrivate);
}

export function preparePublicOrPrivateKey(key: KeyLike) {
  return prepareAsymmetricKey(key, kConsumePublic);
}

export function prepareSecretKey(key, encoding, bufferOnly = false) {
  if (!bufferOnly) {
    if (isKeyObject(key)) {
      if (key.type !== "secret") {
        throw new ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE(key.type, "secret");
      }
      return key[kHandle];
    } else if (isCryptoKey(key)) {
      if (key.type !== "secret") {
        throw new ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE(key.type, "secret");
      }
      return key[kKeyObject][kHandle];
    }
  }
  if (
    typeof key !== "string" && !isArrayBufferView(key) && !isAnyArrayBuffer(key)
  ) {
    throw new ERR_INVALID_ARG_TYPE(
      "key",
      getKeyTypes(!bufferOnly, bufferOnly),
      key,
    );
  }
  return getArrayBufferOrView(key, "key", encoding);
}

export function createSecretKey(
  key: Buffer | ArrayBuffer | ArrayBufferView,
): KeyObject;
export function createSecretKey(key: string, encoding: Encoding): KeyObject;
export function createSecretKey(
  key: string | Buffer | ArrayBuffer | ArrayBufferView,
  encoding?: Encoding,
): KeyObject {
  key = prepareSecretKey(key, encoding, true);
  const handle = new KeyObjectHandle();
  handle.init(kKeyTypeSecret, key);
  return new SecretKeyObject(handle);
}

type PublicKeyInput =
  & ({
    key: Omit<KeyLike, string>;
  } | {
    key: string;
    encoding: Encoding;
  })
  & ({
    format?: "pem" | "jwk";
  } | {
    format: "der";
    type: "pkcs1" | "spki";
  });
export function createPublicKey(key: KeyLike | PublicKeyInput) {
  const { format, type, data, passphrase } = prepareAsymmetricKey(
    key,
    kCreatePublic,
  );
  let handle;
  if (format === "jwk") {
    handle = data;
  } else {
    handle = new KeyObjectHandle();
    handle.init(kKeyTypePublic, data, format, type, passphrase);
  }
  return new PublicKeyObject(handle);
}

type PrivateKeyParams =
  & {
    key: KeyLike;
    encoding?: Encoding;
    passphrase?: string | Buffer;
  }
  & ({
    format?: "pem" | "jwk";
    type?: never;
  } | {
    format: "der";
    type: "pkcs1" | "pkcs8" | "sec1";
  });

export function createPrivateKey(
  key: KeyLike | PrivateKeyParams,
): PrivateKeyObject {
  const { format, type, data, passphrase } = prepareAsymmetricKey(
    key,
    kCreatePrivate,
  );
  let handle;
  if (format === "jwk") {
    handle = data;
  } else {
    handle = new KeyObjectHandle();
    handle.init(kKeyTypePrivate, data, format, type, passphrase);
  }
  return new PrivateKeyObject(handle);
}

export function isKeyObject(obj: unknown): obj is KeyObject {
  return obj != null &&
    (obj as { [kKeyType]?: unknown })[kKeyType] !== undefined;
}

export class CryptoKey {
  constructor() {
    if (!(this instanceof InternalCryptoKey)) {
      throw new ERR_ILLEGAL_CONSTRUCTOR();
    }
  }

  [kInspect](depth: number, options: Parameters<typeof inspect>[1]) {
    if (depth < 0) return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1,
    };

    return `CryptoKey ${
      inspect(
        {
          type: this.type,
          extractable: this.extractable,
          algorithm: this.algorithm,
          usages: this.usages,
        },
        opts,
      )
    }`;
  }

  get type(): KeyObjectType {
    if (!(this instanceof InternalCryptoKey)) {
      throw new ERR_INVALID_THIS("CryptoKey");
    }
    return this[kKeyObject].type;
  }

  get extractable(): boolean {
    if (!(this instanceof InternalCryptoKey)) {
      throw new ERR_INVALID_THIS("CryptoKey");
    }
    return this[kExtractable];
  }

  get algorithm(): string {
    if (!(this instanceof InternalCryptoKey)) {
      throw new ERR_INVALID_THIS("CryptoKey");
    }
    return this[kAlgorithm];
  }

  get usages() {
    if (!(this instanceof InternalCryptoKey)) {
      throw new ERR_INVALID_THIS("CryptoKey");
    }
    return ArrayFrom(this[kKeyUsages]);
  }
}

ObjectDefineProperties(CryptoKey.prototype, {
  type: kEnumerableProperty,
  extractable: kEnumerableProperty,
  algorithm: kEnumerableProperty,
  usages: kEnumerableProperty,
});

export class InternalCryptoKey extends CryptoKey {
  [kKeyObject]: KeyObject;
  [kAlgorithm]: string;
  [kExtractable]: boolean;
  [kKeyUsages]: unknown;

  constructor(
    keyObject: KeyObject,
    algorithm,
    keyUsages,
    extractable: boolean,
  ) {
    super();
    this[kKeyObject] = keyObject;
    this[kAlgorithm] = algorithm;
    this[kExtractable] = extractable;
    this[kKeyUsages] = keyUsages;

    // eslint-disable-next-line no-constructor-return
    return makeTransferable(this);
  }

  [kClone]() {
    const keyObject = this[kKeyObject];
    const algorithm = this.algorithm;
    const extractable = this.extractable;
    const usages = this.usages;

    return {
      data: {
        keyObject,
        algorithm,
        usages,
        extractable,
      },
      deserializeInfo: "internal/crypto/keys:InternalCryptoKey",
    };
  }

  [kDeserialize]({ keyObject, algorithm, usages, extractable }) {
    this[kKeyObject] = keyObject;
    this[kAlgorithm] = algorithm;
    this[kKeyUsages] = usages;
    this[kExtractable] = extractable;
  }
}

export function isCryptoKey(obj: unknown): obj is InternalCryptoKey {
  return obj != null &&
    (obj as { [kKeyObject]?: unknown })[kKeyObject] !== undefined;
}

export type KeyLike =
  | string
  | Buffer
  | ArrayBuffer
  | ArrayBufferView
  | KeyObject;

export default {
  // Public API.
  createSecretKey,
  createPublicKey,
  createPrivateKey,
  KeyObject,
  CryptoKey,
  InternalCryptoKey,

  // These are designed for internal use only and should not be exposed.
  parsePublicKeyEncoding,
  parsePrivateKeyEncoding,
  parseKeyEncoding,
  preparePrivateKey,
  preparePublicOrPrivateKey,
  prepareSecretKey,
  SecretKeyObject,
  PublicKeyObject,
  PrivateKeyObject,
  isKeyObject,
  isCryptoKey,
};
