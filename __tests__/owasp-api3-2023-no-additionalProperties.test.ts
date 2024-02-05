import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api3:2023-no-additionalProperties", [
  {
    name: "valid case: oas2 does not allow additionalProperties by default so dont worry about it",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "object",
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: oas2 can disable if it likes",
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
    name: "valid case: oas3",
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
    name: "valid case: no additionalProperties defined (oas3",
    document: {
      openapi: "3.0.0",
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
    name: "valid case: additionalProperties set to false (oas3)",
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
    errors: [{}],
  },

  {
    name: "invalid case: additionalProperties set to true (oas3)",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "object",
            additionalProperties: true,
          },
        },
      },
    },
    errors: [
      {
        message:
          "If the additionalProperties keyword is used it must be set to false.",
        path: ["components", "schemas", "Foo", "additionalProperties"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
