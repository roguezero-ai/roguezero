/**
 * @roguezero/cli — developer CLI: create · issue · verify · revoke · inspect.
 * A thin shell over `@roguezero/core`. The command functions are exported here so they can
 * be driven programmatically; the `bin` entrypoint is a thin argv parser over them.
 */

export * from "./keystore.js";
export * from "./commands.js";
