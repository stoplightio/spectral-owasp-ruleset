import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api9:2023-inventory-access", [
  {
    name: "valid case: declares x-internal as either true or false",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      servers: [
        { url: "https://api.example.com/", "x-internal": false },
        { url: "https://api-private.example.com/", "x-internal": true },
      ],
    },
    errors: [],
  },

  {
    name: "invalid case: no x-internal declared",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      servers: [{ url: "https://api.example.com/" }],
    },
    errors: [
      {
        message:
          "Declare intended audience of every server by defining servers[0].x-internal as true/false.",
        path: ["servers", "0"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
