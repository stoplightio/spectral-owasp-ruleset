import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-rate-limit-retry-after", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "429": {
                description: "ok",
                headers: {
                  "Retry-After": {
                    description: "standard retry header",
                    schema: {
                      type: "string",
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
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            description: "get",
            responses: {
              "429": {
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
        message: "A 429 response should define a Retry-After header.",
        path: ["paths", "/", "get", "responses", "429", "headers"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
