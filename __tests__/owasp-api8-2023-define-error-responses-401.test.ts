import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api8:2023-define-error-responses-401", [
  {
    name: "valid: defines a 401 response with content",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "401": {
                description: "ok",
                content: {
                  "application/problem+json": {},
                },
              },
            },
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid: 401 is not defined at all",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "200": {
                description: "ok",
                content: {
                  "application/json": {},
                },
              },
            },
          },
        },
      },
    },
    errors: [
      {
        message: "Operation is missing responses[401].",
        path: ["paths", "/", "get", "responses"],
        severity: DiagnosticSeverity.Warning,
      },
      {
        message: "Operation is missing responses[401].content.",
        path: ["paths", "/", "get", "responses"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },

  {
    name: "invalid: 401 exists but content is missing",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "401": {},
            },
          },
        },
      },
    },
    errors: [
      {
        message: "Operation is missing [401].content.",
        path: ["paths", "/", "get", "responses", "401"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
