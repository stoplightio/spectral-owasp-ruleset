import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api8:2023-no-server-http", [
  {
    name: "valid case",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      servers: [{ url: "https://api.example.com/" }],
    },
    errors: [],
  },

  {
    name: "an invalid server.url using http",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      servers: [{ url: "http://api.example.com/" }],
    },
    errors: [
      {
        message:
          "Server URLs must not use http://. Use https:// or wss:// instead.",
        path: ["servers", "0", "url"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "valid case: using a relative path is permitted, deal with the HTTPS yourself",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      servers: [{ url: "/" }],
    },
    errors: [],
  },
]);
