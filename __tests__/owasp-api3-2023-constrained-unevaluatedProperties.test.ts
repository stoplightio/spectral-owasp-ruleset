import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api3:2023-constrained-unevaluatedProperties", [
  {
    name: "valid case: disabled entirely (oas3.1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
            unevaluatedProperties: false,
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: constrained unevaluatedProperties (oas3.1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
            unevaluatedProperties: {
              type: "string",
            },
          },
        },
      },
    },
    errors: [
      {
        message:
          "Objects should not allow unconstrained unevaluatedProperties.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },

  {
    name: "valid case: constrained unevaluatedProperties (oas3.1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
            unevaluatedProperties: {
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
