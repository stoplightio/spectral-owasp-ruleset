import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api8:2023-define-error-validation", [
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
    name: "valid case:400 and 422",
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
    name: "valid case:4XX",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "4XX": {
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
        message: "Missing error response of either 400, 422 or 4XX.",
        path: ["paths", "/", "get", "responses"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
