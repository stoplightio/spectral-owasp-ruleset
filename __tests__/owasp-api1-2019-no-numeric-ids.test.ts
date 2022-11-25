import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api1:2019-no-numeric-ids", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/foo/{id}": {
          get: {
            description: "get",
            parameters: [
              {
                name: "id",
                in: "path",
                required: true,
                schema: {
                  type: "string",
                  format: "uuid",
                },
              },
            ],
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid if its an integer",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/foo/{id}": {
          get: {
            description: "get",
            parameters: [
              {
                name: "id",
                in: "path",
                required: true,
                schema: {
                  type: "integer",
                },
              },
              {
                name: "notanid",
                in: "path",
                required: true,
                schema: {
                  type: "integer",
                },
              },
              {
                name: "underscore_id",
                in: "path",
                required: true,
                schema: {
                  type: "integer",
                },
              },
              {
                name: "hyphen-id",
                in: "path",
                required: true,
                schema: {
                  type: "integer",
                  format: "int32",
                },
              },
              {
                name: "camelId",
                in: "path",
                required: true,
                schema: {
                  type: "integer",
                },
              },
            ],
          },
        },
      },
    },
    errors: [
      {
        message:
          "OWASP API1:2019 - Use random IDs that cannot be guessed. UUIDs are preferred.",
        path: ["paths", "/foo/{id}", "get", "parameters", "0", "schema"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "OWASP API1:2019 - Use random IDs that cannot be guessed. UUIDs are preferred.",
        path: ["paths", "/foo/{id}", "get", "parameters", "2", "schema"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "OWASP API1:2019 - Use random IDs that cannot be guessed. UUIDs are preferred.",
        path: ["paths", "/foo/{id}", "get", "parameters", "3", "schema"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "OWASP API1:2019 - Use random IDs that cannot be guessed. UUIDs are preferred.",
        path: ["paths", "/foo/{id}", "get", "parameters", "4", "schema"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
