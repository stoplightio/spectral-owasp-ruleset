import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-integer-limit", [
  {
    name: "valid case: minimum and maximum",
    document: {
      openapi: "3.1.0",
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
    name: "valid case: exclusiveMinimum and exclusiveMaximum",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            exclusiveMinimum: 1,
            exclusiveMaximum: 99,
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: minimum and exclusiveMaximum",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            minimum: 1,
            exclusiveMaximum: 99,
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: exclusiveMinimum and maximum",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            exclusiveMinimum: 1,
            maximum: 99,
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: only maximum",
    document: {
      openapi: "3.1.0",
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

  {
    name: "invalid case: only exclusiveMaximum",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            exclusiveMaximum: 99,
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
    name: "invalid case: only exclusiveMinimum",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            exclusiveMinimum: 1,
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
    name: "invalid case: only minimum",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            minimum: 1,
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
    name: "invalid case: both minimums and an exclusiveMaximum",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "integer",
            minimum: 1,
            exclusiveMinimum: 1,
            exclusiveMaximum: 4,
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
