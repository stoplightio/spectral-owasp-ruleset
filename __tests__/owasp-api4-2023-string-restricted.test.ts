import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-string-restricted", [
  {
    name: "valid case: format (oas2)",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "string",
          format: "email",
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: format (oas2)",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      definitions: {
        Foo: {
          type: "string",
          pattern: "/^foo/",
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: format (oas3)",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "string",
            format: "email",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: pattern (oas3)",
    document: {
      openapi: "3.0.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "string",
            pattern: "/^foo/",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: format (oas3.1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: ["null", "string"],
            format: "email",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: pattern (oas3.1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: ["null", "string"],
            pattern: "/^foo/",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case: enum (oas3)",
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
    name: "valid case: format + pattern (oas3.1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          foo: {
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
    name: "valid case: const (oas3.1)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: "string",
            const: "CONSTANT",
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: neither format or pattern (oas2)",
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
          "Schema of type string should specify a format, pattern, enum, or const.",
        path: ["definitions", "Foo"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },

  {
    name: "invalid case: neither format or pattern (oas3)",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        schemas: {
          Foo: {
            type: ["null", "string"],
          },

          Bar: {
            type: "string",
          },
        },
      },
    },
    errors: [
      {
        message:
          "Schema of type string should specify a format, pattern, enum, or const.",
        path: ["components", "schemas", "Foo"],
        severity: DiagnosticSeverity.Warning,
      },
      {
        message:
          "Schema of type string should specify a format, pattern, enum, or const.",
        path: ["components", "schemas", "Bar"],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
