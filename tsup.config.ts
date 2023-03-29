import type { Options } from 'tsup';
export default <Options>{
  entry: ["src/ruleset.ts"],
  clean: true,
  dts: true,
  target: "es2018",
  format: ["cjs", "esm"],
  sourcemap: true,
  noExternal: ["@stoplight/types"],
  external: ["@stoplight/spectral-core"],
  footer({ format }) {
    if (format === "cjs") {
      return {
        js: "module.exports = module.exports.default;",
      };
    }

    return {};
  },
};
