import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api5:2023-admin-security-unique", [
  {
    name: "valid case: different security schemes",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/public/export": {
          get: {
            security: [
              {
                ApiKey: [],
              },
            ],
          },
        },
        "/admin/export": {
          get: {
            security: [
              {
                Oauth2: ["admin_scope"],
              },
            ],
          },
        },
      },
      components: {
        securitySchemes: {
          ApiKey: {},
          Oauth2: {},
        },
      },
    },
    errors: [],
  },

  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/public/export": {
          get: {
            security: [
              {
                oauth2: ["read_scope"],
              },
            ],
          },
        },
        "/admin/export": {
          get: {
            security: [
              {
                oauth2: ["admin_scope"],
              },
            ],
          },
        },
      },
      components: {
        securitySchemes: {
          oauth2: {},
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: oauth2 is used for both with no scopes",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/public/export": {
          get: {
            security: [{ oauth2: [] }],
          },
        },
        "/admin/export": {
          get: {
            security: [{ oauth2: [] }],
          },
        },
      },
      components: {
        securitySchemes: {
          oauth2: {},
        },
      },
    },
    errors: [
      {
        message:
          "Admin endpoint /admin/export has the same security requirement as a non-admin endpoint.",
        path: ["paths", "/admin/export", "get", "security", "0"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "invalid case: oauth2 is used for both with same scopes",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/public/export": {
          get: {
            security: [{ oauth2: ["foo"] }],
          },
        },
        "/admin/export": {
          get: {
            security: [{ oauth2: ["foo"] }],
          },
        },
      },
      components: {
        securitySchemes: {
          oauth2: {},
        },
      },
    },
    errors: [
      {
        message:
          "Admin endpoint /admin/export has the same security requirement as a non-admin endpoint.",
        path: ["paths", "/admin/export", "get", "security", "0"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
