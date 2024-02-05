import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api3:2023-no-unevaluatedProperties", [
  {
    name: "valid case: oas3_1",
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
    name: "valid case: no unevaluatedProperties defined (oas3_1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: unevaluatedProperties set to false (oas3_1)",
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
    name: "invalid case: unevaluatedProperties set to true (oas3_1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
            unevaluatedProperties: true,
          },
        },
      },
    },
    errors: [
      {
        message:
          "If the unevaluatedProperties keyword is used it must be set to false.",
        path: ["components", "schemas", "Foo", "unevaluatedProperties"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
