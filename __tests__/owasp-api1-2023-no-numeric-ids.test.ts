import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api1:2023-no-numeric-ids", [
  {
    name: "valid case: uuid",
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
    name: "valid case: ulid",
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
                  format: "ulid",
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
    name: "valid case: random",
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
                  example: "sfdjkhjk24kd9s",
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
          "Use random IDs that cannot be guessed. UUIDs are preferred but any other random string will do.",
        path: ["paths", "/foo/{id}", "get", "parameters", "0", "schema"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Use random IDs that cannot be guessed. UUIDs are preferred but any other random string will do.",
        path: ["paths", "/foo/{id}", "get", "parameters", "2", "schema"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Use random IDs that cannot be guessed. UUIDs are preferred but any other random string will do.",
        path: ["paths", "/foo/{id}", "get", "parameters", "3", "schema"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Use random IDs that cannot be guessed. UUIDs are preferred but any other random string will do.",
        path: ["paths", "/foo/{id}", "get", "parameters", "4", "schema"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
