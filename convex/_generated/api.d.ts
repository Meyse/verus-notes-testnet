/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as auth from "../auth.js";
import type * as crons from "../crons.js";
import type * as folders from "../folders.js";
import type * as lib_authLifecycle from "../lib/authLifecycle.js";
import type * as lib_authPolicy from "../lib/authPolicy.js";
import type * as lib_backendAuth from "../lib/backendAuth.js";
import type * as lib_encoding from "../lib/encoding.js";
import type * as lib_encryptedRecords from "../lib/encryptedRecords.js";
import type * as lib_privacyMetadata from "../lib/privacyMetadata.js";
import type * as lib_signerAttestation from "../lib/signerAttestation.js";
import type * as notes from "../notes.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  auth: typeof auth;
  crons: typeof crons;
  folders: typeof folders;
  "lib/authLifecycle": typeof lib_authLifecycle;
  "lib/authPolicy": typeof lib_authPolicy;
  "lib/backendAuth": typeof lib_backendAuth;
  "lib/encoding": typeof lib_encoding;
  "lib/encryptedRecords": typeof lib_encryptedRecords;
  "lib/privacyMetadata": typeof lib_privacyMetadata;
  "lib/signerAttestation": typeof lib_signerAttestation;
  notes: typeof notes;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
