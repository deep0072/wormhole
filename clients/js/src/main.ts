#!/usr/bin/env node
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
// Side effects are here to trigger before the afflicted libraries' on-import warnings can be emitted.
// It is also imported so that it can side-effect without being tree-shaken.
import "./side-effects";
// https://github.com/yargs/yargs/blob/main/docs/advanced.md#example-command-hierarchy-using-indexmjs
import * as aptos from "./cmds/aptos";
import * as editVaa from "./cmds/editVaa";
import * as evm from "./cmds/evm";
import * as generate from "./cmds/generate";
import * as info from "./cmds/info";
import * as near from "./cmds/near";
import * as parse from "./cmds/parse";
import * as recover from "./cmds/recover";
import * as submit from "./cmds/submit";
import * as sui from "./cmds/sui";
import * as verifyVaa from "./cmds/verifyVaa";

yargs(hideBin(process.argv))
  // https://github.com/yargs/yargs/blob/main/docs/advanced.md#commanddirdirectory-opts
  // can't use `.commandDir` because bundling + tree-shaking
  .command(aptos)
  .command(editVaa)
  .command(evm)
  .command(generate)
  .command(info)
  .command(near)
  .command(parse)
  .command(recover)
  .command(submit)
  .command(sui)
  .command(verifyVaa)
  .strict()
  .demandCommand().argv;
