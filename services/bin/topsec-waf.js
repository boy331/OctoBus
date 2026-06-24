#!/usr/bin/env node

import { fileURLToPath } from "node:url";
import { runServiceMain } from "@chaitin-ai/octobus-sdk";

import { service } from "../topsec__waf/src/service.js";

runServiceMain(service, {
  entryFile: fileURLToPath(new URL("../topsec__waf/bin/topsec-waf.js", import.meta.url)),
});
