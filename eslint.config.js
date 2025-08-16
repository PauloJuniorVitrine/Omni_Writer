// ESLint v9+ config migrado de .eslintrc.json
import js from "@eslint/js";
import airbnbBase from "eslint-config-airbnb-base";

export default [
  js.config({
    env: {
      browser: true,
      es2021: true,
      jest: true,
    },
  }),
  ...airbnbBase,
  {
    rules: {
      "no-console": "warn",
      "no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
      "max-len": ["error", { "code": 100 }],
    },
  },
]; 