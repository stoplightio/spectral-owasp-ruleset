import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api3:2019-define-error-validation", [
  {
    name: "valid case: 400",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "400": {
                description: "classic validation fail",
              },
            },
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: 422",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "422": {
                description: "classic validation fail",
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
            responses: {
              "200": {
                description: "ok",
              },
            },
          },
        },
      },
    },
    errors: [
      {
        message: "Missing error validation response of either 400 or 422.",
        path: ["paths", "/", "get", "responses"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
