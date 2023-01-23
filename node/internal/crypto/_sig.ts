// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

import { Buffer } from "../../buffer.ts";
import { notImplemented } from "../../_utils.ts";
import { BinaryLike } from "./types.ts";
import type { KeyObjectHandle, PKEncodingType, PKFormatType } from "./_keys.ts";

export enum DSASigEnc {
  kSigEncDER,
  kSigEncP1363,
}

export class _Sign {
  init(algorithm: string) {
  }

  update(data: BinaryLike, encoding: string) {
  }

  sign(
    data: BinaryLike | KeyObjectHandle,
    format: string | PKFormatType | undefined,
    type: PKEncodingType | undefined,
    passphrase: string | Buffer | undefined,
    rsaPadding: number | undefined,
    pssSaltLength: number | undefined,
    dsaSigEnc: DSASigEnc,
  ): Buffer {
    notImplemented("_Sign.sign");
  }
}

export class _Verify {
  init(algorithm: string) {
  }
}
