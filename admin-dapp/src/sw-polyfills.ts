// Node global polyfills for the service worker.
//
// vite-plugin-node-polyfills injects Buffer/process/global into the *app*
// bundle, but vite-plugin-pwa's injectManifest builds sw.js as a *separate*
// bundle the plugin never processes. @enbox/browser (via its DWN/crypto deps)
// references Buffer and process at module-eval time inside activatePolyfills(),
// so without these the worker throws `ReferenceError: Buffer is not defined`
// at sw.js:1 and the DWeb networking layer never activates.
//
// This module is imported *first* in sw.ts; under ES import ordering its
// side effects run before the @enbox/browser module is evaluated.
import { Buffer } from "buffer";
import process from "process";

const globals = globalThis as unknown as {
  global?: typeof globalThis;
  Buffer?: typeof Buffer;
  process?: typeof process;
};

globals.global ??= globalThis;
globals.Buffer ??= Buffer;
globals.process ??= process;
