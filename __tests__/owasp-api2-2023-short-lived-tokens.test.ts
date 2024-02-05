import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

const authorizationCodeFlow = {
  authorizationUrl: "https://example.com/oauth/authorize",
  tokenUrl: "https://example.com/oauth/token",
  scopes: {
    read_scope: "Read access to the protected resource",
    write_scope: "Write access to the protected resource",
  },
};

const oauth2SchemeWithRefreshUrl = {
  type: "oauth2",
  flows: {
    authorizationCode: {
      ...authorizationCodeFlow,
      refreshUrl: "https://example.com/oauth/refresh",
    },
  },
};

const oauth2SchemeWithoutRefreshUrl = {
  type: "oauth2",
  flows: {
    authorizationCode: authorizationCodeFlow,
  },
};

testRule("owasp:api2:2023-short-lived-access-tokens", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        securitySchemes: {
          oauth2: oauth2SchemeWithRefreshUrl,
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      components: {
        securitySchemes: {
          oauth2: oauth2SchemeWithoutRefreshUrl,
        },
      },
    },
    errors: [
      {
        message:
          "Authentication scheme does not appear to support refresh tokens, meaning access tokens likely do not expire.",
        path: [
          "components",
          "securitySchemes",
          "oauth2",
          "flows",
          "authorizationCode",
        ],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
