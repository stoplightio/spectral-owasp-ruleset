import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-integer-limit-legacy", [
  {
    name: "valid case: oas2",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "integer",
          minimum: 1,
          maximum: 99,
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: oas3.0",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            minimum: 1,
            maximum: 99,
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: oas2 missing maximum",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "integer",
        },
      },
    },
    errors: [
      {
        message: "Schema of type integer must specify minimum and maximum.",
        path: ["definitions", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "invalid case: oas3.0 missing maximum",
    document: {
      openapi: "3.0.0",
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
        message: "Schema of type integer must specify minimum and maximum.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "invalid case: oas2 has maximum but missing minimum",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "integer",
          maximum: 99,
        },
      },
    },
    errors: [
      {
        message: "Schema of type integer must specify minimum and maximum.",
        path: ["definitions", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "invalid case: oas3.0 has maximum but missing minimum",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            maximum: 99,
          },
        },
      },
    },
    errors: [
      {
        message: "Schema of type integer must specify minimum and maximum.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
