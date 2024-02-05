import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

testRule("owasp:api9:2023-inventory-environment", [
  {
    name: "valid case: mentions one keyword in each server",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      servers: [
        { url: "https://api.example.com/", description: "Production" },
        { url: "https://preprod.example.com/", description: "Preproduction" },
        { url: "https://api-stag.example.com/", description: "Staging" },
        { url: "https://api-test.example.com/", description: "test" },
      ],
    },
    errors: [],
  },

  {
    name: "invalid case: no description declared",
    document: {
      openapi: "3.1.0",
      info: { version: "1.0" },
      paths: { "/": {} },
      servers: [
        { url: "https://api.example.com/", description: "API" },
        { url: "https://preprod.example.com/", description: "Trial" },
        { url: "https://api-stag.example.com/", description: "Trial" },
        { url: "https://api-test.example.com/", description: "muck about" },
      ],
    },
    errors: [
      {
        message:
          "Declare intended environment in server descriptions using terms like local, staging, production.",
        path: ["servers", "0", "description"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Declare intended environment in server descriptions using terms like local, staging, production.",
        path: ["servers", "1", "description"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Declare intended environment in server descriptions using terms like local, staging, production.",
        path: ["servers", "2", "description"],
        severity: DiagnosticSeverity.Error,
      },
      {
        message:
          "Declare intended environment in server descriptions using terms like local, staging, production.",
        path: ["servers", "3", "description"],
        severity: DiagnosticSeverity.Error,
      },
    ],
  },
]);
