import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api8:2023-define-cors-origin", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0", contact: {} },
      paths: {
        "/": {
          get: {
            responses: {
              "200": {
                description: "ok",
                headers: {
                  "Access-Control-Allow-Origin": {
                    schema: {
                      type: "string",
                      examples: ["*"],
                    },
                  },
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
    name: "invalid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0", contact: {} },
      paths: {
        "/a": {
          get: {
            responses: {
              "200": {
                description: "ok",
                headers: {
                  "Some-Other-Headers": {
                    schema: {
                      type: "string",
                      examples: ["*"],
                    },
                  },
                },
              },
            },
          },
        },
        "/b": {
          get: {
            responses: {
              "200": {
                description: "ok",
                headers: {},
              },
            },
          },
        },
      },
    },
    errors: [
      {
        message:
          "Header `headers.Access-Control-Allow-Origin` should be defined on all responses.",
        path: ["paths", "/a", "get", "responses", "200", "headers"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Header `headers.Access-Control-Allow-Origin` should be defined on all responses.",
        path: ["paths", "/b", "get", "responses", "200", "headers"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
