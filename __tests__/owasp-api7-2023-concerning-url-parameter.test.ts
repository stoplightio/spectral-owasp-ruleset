import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api7:2023-concerning-url-parameter", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      "/foo": {
        get: {
          description: "get",
          parameters: {
            name: "not-a-redirect",
            in: "query",
          },
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
        "/foo": {
          get: {
            description: "get",
            parameters: [
              {
                name: "callback",
                in: "query",
              },
              {
                name: "callbackUrl",
                in: "query",
              },
              {
                name: "callback_url",
                in: "query",
              },
              {
                name: "redirect",
                in: "query",
              },
              {
                name: "redirectUrl",
                in: "query",
              },
              {
                name: "redirect_url",
                in: "query",
              },
            ],
          },
        },
      },
    },
    errors: [
      {
        message:
          "Make sure to review the way this URL is handled to protect against Server Side Request Forgery.",
        severity: DiagnosticSeverity.Information,
      },
      {
        message:
          "Make sure to review the way this URL is handled to protect against Server Side Request Forgery.",
        severity: DiagnosticSeverity.Information,
      },
      {
        message:
          "Make sure to review the way this URL is handled to protect against Server Side Request Forgery.",
        severity: DiagnosticSeverity.Information,
      },

      {
        message:
          "Make sure to review the way this URL is handled to protect against Server Side Request Forgery.",
        severity: DiagnosticSeverity.Information,
      },
      {
        message:
          "Make sure to review the way this URL is handled to protect against Server Side Request Forgery.",
        severity: DiagnosticSeverity.Information,
      },
      {
        message:
          "Make sure to review the way this URL is handled to protect against Server Side Request Forgery.",
        severity: DiagnosticSeverity.Information,
      },
    ],
  },
]);
