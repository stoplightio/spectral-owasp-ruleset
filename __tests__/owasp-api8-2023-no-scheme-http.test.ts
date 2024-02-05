import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api8:2023-no-scheme-http", [
  {
    name: "valid case: https",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      host: "example.com",
      schemes: ["https"],
    },
    errors: [],
  },

  {
    name: "valid case: wss",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      host: "example.com",
      schemes: ["wss"],
    },
    errors: [],
  },

  {
    name: "an invalid server.url using http",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      host: "example.com",
      schemes: ["http"],
    },
    errors: [
      {
        message: "Server schemes must not use http. Use https or wss instead.",
        path: ["schemes", "0"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "an invalid server.url using http and https",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      host: "example.com",
      schemes: ["https", "http"],
    },
    errors: [
      {
        message: "Server schemes must not use http. Use https or wss instead.",
        path: ["schemes", "1"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },

  {
    name: "an invalid server using ftp",
    document: {
      swagger: "2.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      host: "example.com",
      schemes: ["ftp"],
    },
    errors: [
      {
        message: "Server schemes must not use http. Use https or wss instead.",
        path: ["schemes", "0"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
