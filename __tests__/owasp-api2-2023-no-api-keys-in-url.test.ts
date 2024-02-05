import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api2:2023-no-api-keys-in-url", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        securitySchemes: {
          "API Key in URL": {
            type: "apiKey",
            in: "header",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        securitySchemes: {
          "API Key in Query": {
            type: "apiKey",
            in: "query",
          },
          "API Key in Path": {
            type: "apiKey",
            in: "path",
          },
        },
      },
    },
    errors: [
      {
        message:
          'API Key passed in URL: "query" must not match the pattern "^(path|query)$".',
        path: ["components", "securitySchemes", "API Key in Query", "in"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          'API Key passed in URL: "path" must not match the pattern "^(path|query)$".',
        path: ["components", "securitySchemes", "API Key in Path", "in"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
