import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-string-limit", [
  {
    name: "valid case: oas2",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "string",
          maxLength: 99,
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
            type: "string",
            maxLength: 99,
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
          Foo: {
            type: ["null", "string"],
            maxLength: 99,
          },
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
            type: "string",
            enum: ["a", "b", "c"],
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
          Foo: {
            type: "string",
            const: "constant",
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
          Foo: {
            type: "string",
            const: "constant",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: pattern and maxLength, oas3.1",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "string",
            format: "hex",
            pattern: "^[0-9a-fA-F]+$",
            maxLength: 16,
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: oas2 missing maxLength",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "string",
        },
      },
    },
    errors: [
      {
        message:
          "Schema of type string must specify maxLength, enum, or const.",
        path: ["definitions", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "invalid case: oas3.0 missing maxLength",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "string",
          },
        },
      },
    },
    errors: [
      {
        message:
          "Schema of type string must specify maxLength, enum, or const.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
  {
    name: "invalid case: oas3.1 missing maxLength",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: ["null", "string"],
          },
        },
      },
    },
    errors: [
      {
        message:
          "Schema of type string must specify maxLength, enum, or const.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
  {
    name: "valid case: format: date-time does not need maxLength",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: ["null", "string"],
          },
        },
      },
    },
    errors: [
      {
        message:
          "Schema of type string must specify maxLength, enum, or const.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
