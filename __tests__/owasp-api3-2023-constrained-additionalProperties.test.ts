import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api3:2023-constrained-additionalProperties", [
  {
    name: "valid case: disabled entirely (oas2)",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "object",
          additionalProperties: false,
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: disabled entirely (oas3)",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
            additionalProperties: false,
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: constrained additionalProperties (oas3)",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
            additionalProperties: {
              type: "string",
            },
          },
        },
      },
    },
    errors: [
      {
        message: "Objects should not allow unconstrained additionalProperties.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },

  {
    name: "valid case: constrained additionalProperties (oas3)",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
            additionalProperties: {
              type: "string",
            },
            maxProperties: 1,
          },
        },
      },
    },
    errors: [],
  },
]);
