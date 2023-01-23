// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
// Copyright 2014-2017 browserify-aes contributors. All rights reserved. MIT license.
// Copyright 2013 Maxwell Krohn. All rights reserved. MIT license.
// Copyright 2009-2013 Jeff Mott. All rights reserved. MIT license.

import * as CBC from "./cbc.js";
import * as CFB from "./cfb.js";
import * as CFB1 from "./cfb1.js";
import * as CFB8 from "./cfb8.js";
import * as CTR from "./ctr.js";
import * as ECB from "./ecb.js";
import { MODES } from "./list.ts";
import * as OFB from "./ofb.js";
export { MODES };

const GCM = CTR;

const modeModules = {
  ECB,
  CBC,
  CFB,
  CFB8,
  CFB1,
  OFB,
  CTR,
  GCM,
};

for (const mode of Object.values(MODES)) {
  mode.module = modeModules[mode.mode];
}
