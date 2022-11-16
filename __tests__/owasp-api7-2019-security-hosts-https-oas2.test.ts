import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api7:2019-security-hosts-https-oas2", [
  {
    name: "valid case",
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
        message:
          "All servers defined MUST use https, and no other protocol is permitted.",
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
        message:
          "All servers defined MUST use https, and no other protocol is permitted.",
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
        message:
          "All servers defined MUST use https, and no other protocol is permitted.",
        path: ["schemes", "0"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
