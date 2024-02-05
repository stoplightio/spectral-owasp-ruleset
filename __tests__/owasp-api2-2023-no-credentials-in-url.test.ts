import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api2:2023-no-credentials-in-url", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      "/foo/{id}": {
        get: {
          description: "get",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
            },
            {
              name: "filter",
              in: "query",
              required: true,
            },
          ],
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
      paths: {
        "/foo/{api-key}": {
          get: {
            description: "get",
            parameters: [
              {
                name: "client_secret",
                in: "query",
                required: true,
              },
              {
                name: "token",
                in: "query",
                required: true,
              },
              {
                name: "refresh_token",
                in: "query",
                required: true,
              },
              {
                name: "id_token",
                in: "query",
                required: true,
              },
              {
                name: "password",
                in: "query",
                required: true,
              },
              {
                name: "secret",
                in: "query",
                required: true,
              },
              {
                name: "apikey",
                in: "query",
                required: true,
              },
              {
                name: "api-key",
                in: "path",
                required: true,
              },
              {
                name: "API-KEY",
                in: "query",
                required: true,
              },
            ],
          },
        },
      },
    },
    errors: [
      {
        message:
          "Security credentials detected in path parameter: client_secret.",
        severity: DiagnosticSeverity.Error,
      },
      {
        message: "Security credentials detected in path parameter: token.",
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Security credentials detected in path parameter: refresh_token.",
        severity: DiagnosticSeverity.Error,
      },

      {
        message: "Security credentials detected in path parameter: id_token.",
        severity: DiagnosticSeverity.Error,
      },
      {
        message: "Security credentials detected in path parameter: password.",
        severity: DiagnosticSeverity.Error,
      },
      {
        message: "Security credentials detected in path parameter: secret.",
        severity: DiagnosticSeverity.Error,
      },
      {
        message: "Security credentials detected in path parameter: apikey.",
        severity: DiagnosticSeverity.Error,
      },
      {
        message: "Security credentials detected in path parameter: api-key.",
        severity: DiagnosticSeverity.Error,
      },
      {
        message: "Security credentials detected in path parameter: API-KEY.",
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
