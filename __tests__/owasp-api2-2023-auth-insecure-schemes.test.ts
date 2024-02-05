import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api2:2023-auth-insecure-schemes", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        securitySchemes: {
          "bearer is ok": {
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
          "bad negotiate": {
            type: "http",
            scheme: "negotiate",
          },
          "bad oauth": {
            type: "http",
            scheme: "oauth",
          },
        },
      },
    },
    errors: [
      {
        message:
          "Authentication scheme is considered outdated or insecure: negotiate.",
        path: ["components", "securitySchemes", "bad negotiate", "scheme"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Authentication scheme is considered outdated or insecure: oauth.",
        path: ["components", "securitySchemes", "bad oauth", "scheme"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
