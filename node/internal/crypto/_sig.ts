// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

import { Buffer } from "../../buffer.ts";
import { notImplemented } from "../../_utils.ts";
import { KeyObjectHandle } from "./_keys.ts";

export class _Sign {
  init(algorithm: string) {
  }

  sign(
    data: string | KeyObjectHandle | Buffer,
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
