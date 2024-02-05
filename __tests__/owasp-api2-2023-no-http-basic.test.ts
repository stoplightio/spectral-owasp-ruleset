import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api2:2023-no-http-basic", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        securitySchemes: {
          "anything-else": {
            type: "http",
            scheme: "bearer",
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
          "please-hack-me": {
            type: "http",
            scheme: "basic",
          },
        },
      },
    },
    errors: [
      {
        message:
          "Security scheme uses HTTP Basic. Use a more secure authentication method, like OAuth 2, or OpenID.",
        path: ["components", "securitySchemes", "please-hack-me", "scheme"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
