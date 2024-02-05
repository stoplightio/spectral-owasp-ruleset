import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api2:2023-jwt-best-practices", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        securitySchemes: {
          "bad oauth2": {
            type: "oauth2",
            description: "These JWTs use RFC8725.",
          },
          "bad bearer jwt": {
            type: "http",
            bearerFormat: "jwt",
            description: "These JWTs use RFC8725.",
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
          "bad oauth2": {
            type: "oauth2",
            description:
              "No way of knowing if these JWTs are following best practices.",
          },
          "bad bearer jwt": {
            type: "http",
            bearerFormat: "jwt",
            description:
              "No way of knowing if these JWTs are following best practices.",
          },
        },
      },
    },
    errors: [
      {
        message:
          "Security schemes using JWTs must explicitly declare support for RFC8725 in the description.",
        path: ["components", "securitySchemes", "bad oauth2", "description"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Security schemes using JWTs must explicitly declare support for RFC8725 in the description.",
        path: [
          "components",
          "securitySchemes",
          "bad bearer jwt",
          "description",
        ],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
