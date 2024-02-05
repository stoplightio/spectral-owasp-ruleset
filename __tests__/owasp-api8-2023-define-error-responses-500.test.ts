import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api8:2023-define-error-responses-500", [
  {
    name: "valid: defines a 500 response with content",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "500": {
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
    name: "invalid: 500 is not defined at all",
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
        message: "Operation is missing responses[500].",
        path: ["paths", "/", "get", "responses"],
        severity: DiagnosticSeverity.Warning,
      },
      {
        message: "Operation is missing responses[500].content.",
        path: ["paths", "/", "get", "responses"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },

  {
    name: "invalid: 500 exists but content is missing",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "500": {},
            },
          },
        },
      },
    },
    errors: [
      {
        message: "Operation is missing [500].content.",
        path: ["paths", "/", "get", "responses", "500"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
