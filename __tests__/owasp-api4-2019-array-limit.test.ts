import { DiagnosticSeverity } from "@stoplight/types";
import testRule from "./__helpers__/helper";

// TODO oas3.1 tests

testRule("owasp:api4:2019-array-limit", [
	{
		name: "valid case: oas2",
		document: {
			swagger: "2.0",
			info: { version: "1.0" },
			definitions: {
        Foo: {
          type: "array",
          maxItems: 99,
        },
			},
		},
		errors: [],
	},

  {
		name: "valid case: oas3",
		document: {
			openapi: "3.0.0",
			info: { version: "1.0" },
			components: {
				schemas: {
					Foo: {
						type: "array",
            maxItems: 99,
					},
				},
			},
		},
		errors: [],
	},

	{
		name: "invalid case: oas2 missing maxItems",
		document: {
			swagger: "2.0",
			info: { version: "1.0" },
			definitions: {
        Foo: {
          type: "array"
        },
			},
		},
		errors: [
			{
				message: "Schema of type array must specify maxItems.",
				path: ["definitions", "Foo"],
				severity: DiagnosticSeverity.Error,
			}
		],
	},

	{
		name: "invalid case: oas3 missing maxItems",
		document: {
			openapi: "3.0.0",
			info: { version: "1.0" },
			components: {
				schemas: {
					Foo: {
						type: "array"
					},
				},
			},
		},
		errors: [
			{
				message: "Schema of type array must specify maxItems.",
				path: ["components", "schemas", "Foo"],
				severity: DiagnosticSeverity.Error,
			}
		],
	},
]);
