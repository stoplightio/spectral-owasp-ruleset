import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-integer-format", [
  {
    name: "valid case: format - int32",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            format: "int32",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: format - int64",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            format: "int64",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: format - whatever",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            format: "whatever",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: no format",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
          },
        },
      },
    },
    errors: [
      {
        message: "Schema of type integer must specify format (int32 or int64).",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
