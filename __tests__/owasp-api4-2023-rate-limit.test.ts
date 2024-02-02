import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api4:2023-rate-limit", [
  {
    name: "valid use of IETF Draft HTTP RateLimit-* Headers",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "201": {
                description: "ok",
                headers: {
                  "RateLimit-Limit": {
                    schema: {
                      type: "string",
                    },
                  },
                  "RateLimit-Reset": {
                    schema: {
                      type: "string",
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid use of IETF Draft HTTP RateLimit Headers",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "201": {
                description: "ok",
                headers: {
                  RateLimit: {
                    schema: {
                      type: "string",
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid use of Twitter-style Rate Limit Headers",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "201": {
                description: "ok",
                headers: {
                  "X-Rate-Limit-Limit": {
                    schema: {
                      type: "string",
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "valid use of GitHub-style Rate Limit Headers",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            responses: {
              "201": {
                description: "ok",
                headers: {
                  "X-RateLimit-Limit": {
                    schema: {
                      type: "string",
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    errors: [],
  },

  {
    name: "invalid case: no limit headers set",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            description: "get",
            responses: {
              "201": {
                description: "ok",
              },
            },
          },
        },
      },
    },
    errors: [
      {
        message:
          "All 2XX and 4XX responses should define rate limiting headers.",
        path: ["paths", "/", "get", "responses", "201"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "invalid case: no rate limit headers set",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: {
        "/": {
          get: {
            description: "get",
            responses: {
              "201": {
                description: "ok",
                headers: {
                  SomethingElse: {
                    schema: {
                      type: "string",
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    errors: [
      {
        message:
          "All 2XX and 4XX responses should define rate limiting headers.",
        path: ["paths", "/", "get", "responses", "201", "headers"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
