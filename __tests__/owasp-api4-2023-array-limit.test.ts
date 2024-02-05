import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-array-limit", [
  {
    name: "valid case: oas2",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "array",
          maxItems: 99,
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: oas3",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "array",
            maxItems: 99,
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: oas3.1",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          type: {
            type: "string",
            maxLength: 99,
          },
          User: {
            type: "object",
            properties: {
              type: {
                enum: ["user", "admin"],
              },
            },
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: oas2 missing maxItems",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "array",
        },
      },
    },
    errors: [
      {
        message: "Schema of type array must specify maxItems.",
        path: ["definitions", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "invalid case: oas3 missing maxItems",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "array",
          },
        },
      },
    },
    errors: [
      {
        message: "Schema of type array must specify maxItems.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
