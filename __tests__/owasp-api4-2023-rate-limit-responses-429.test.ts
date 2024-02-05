import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-rate-limit-responses-429", [
  {
    name: "valid: defines a 429 response with content",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "429": {
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
    name: "invalid: 429 is not defined at all",
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
        message:
          "Operation is missing rate limiting response in responses[429].",
        path: ["paths", "/", "get", "responses"],
        severity: DiagnosticSeverity.Warning,
      },
      {
        message:
          "Operation is missing rate limiting response in responses[429].content.",
        path: ["paths", "/", "get", "responses"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },

  {
    name: "invalid: 429 exists but content is missing",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "429": {},
            },
          },
        },
      },
    },
    errors: [
      {
        message:
          "Operation is missing rate limiting response in [429].content.",
        path: ["paths", "/", "get", "responses", "429"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
