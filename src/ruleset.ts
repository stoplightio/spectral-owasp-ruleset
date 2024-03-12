import {
  defined,
  truthy,
  pattern,
  schema,
  falsy,
  xor,
} from "@stoplight/spectral-functions";
import { oas2, oas3, oas3_0, oas3_1 } from "@stoplight/spectral-formats";
import { DiagnosticSeverity } from "@stoplight/types";
import checkSecurity from "./functions/checkSecurity";
import differentSecuritySchemes from "./functions/differentSecuritySchemes";

export default {
  formats: [oas2, oas3],

  aliases: {
    ArrayProperties: {
      targets: [
        {
          formats: [oas2, oas3_0],
          given: [
            // Check for type: 'array'
            '$..[?(@ && @.type=="array")]',
          ],
        },
        {
          formats: [oas3_1],
          given: [
            // Still check for type: 'array'
            '$..[?(@ && @.type=="array")]',

            // also check for type: ['array', ...]
            '$..[?(@ && @.type && @.type.constructor.name === "Array" && @.type.includes("array"))]',
          ],
        },
      ],
    },
    IntegerProperties: {
      targets: [
        {
          formats: [oas2, oas3_0],
          given: [
            // Check for type: 'string'
            '$..[?(@ && @.type=="integer")]',
          ],
        },
        {
          formats: [oas3_1],
          given: [
            // Still check for type: 'integer'
            '$..[?(@ && @.type=="integer")]',

            // also check for type: ['integer', ...]
            '$..[?(@ && @.type && @.type.constructor.name === "Array" && @.type.includes("integer"))]',
          ],
        },
      ],
    },
    StringProperties: {
      targets: [
        {
          formats: [oas2, oas3_0],
          given: [
            // Check for type: 'string'
            '$..[?(@ && @.type=="string")]',
          ],
        },
        {
          formats: [oas3_1],
          given: [
            // Still check for type: 'string'
            '$..[?(@ && @.type=="string")]',

            // also check for type: ['string', ...]
            '$..[?(@ && @.type && @.type.constructor.name === "Array" && @.type.includes("string"))]',
          ],
        },
      ],
    },
  },

  rules: {
    /**
     * API1:2023 - Broken Object Level Authorization
     * https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
     *
     * Use case
     * - ❌ API call parameters use the ID of the resource accessed through the API /api/shop1/financial_info.
     * - ❌ Attackers replace the IDs of their resources with a different one which they guessed through /api/shop2/financial_info.
     * - ❌ The API does not check permissions and lets the call through.
     * - ✅ Problem is aggravated if IDs can be enumerated /api/123/financial_info.
     *
     * How to prevent
     * - ❌ Implement authorization checks with user policies and hierarchy.
     * - ❌ Do not rely on IDs that the client sends. Use IDs stored in the session object instead.
     * - ❌ Check authorization for each client request to access database.
     * - ✅ Use random IDs that cannot be guessed (UUIDs).
     */

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api1:2023-no-numeric-ids": {
      description:
        "Use random IDs that cannot be guessed. UUIDs are preferred but any other random string will do.",
      severity: DiagnosticSeverity.Error,
      given:
        '$.paths..parameters[*][?(@property === "name" && (@ === "id" || @.match(/(_id|Id|-id)$/)))]^.schema',
      then: {
        function: schema,
        functionOptions: {
          schema: {
            type: "object",
            not: {
              properties: {
                type: {
                  const: "integer",
                },
              },
            },
          },
        },
      },
    },

    /**
     * API2:2023 — Broken Authentication
     * https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
     *
     * Use case
     * - ✅ Unprotected APIs that are considered “internal”
     * - ✅ Weak authentication that does not follow industry best practices
     * - ✅ Weak API keys that are not rotated
     * - ❌ Passwords that are weak, plain text, encrypted, poorly hashed, shared, or default passwords
     * - 🤷 Authentication susceptible to brute force attacks and credential stuffing
     * - ✅ Credentials and keys included in URLs
     * - ✅ Lack of access token validation (including JWT validation)
     * - ✅ Unsigned or weakly signed non-expiring JWTs
     *
     * How to prevent
     * - ❌ APIs for password reset and one-time links also allow users to authenticate, and should be protected just as rigorously.
     * - ✅ Use standard authentication, token generation, password storage, and multi-factor authentication (MFA).
     * - ✅ Use short-lived access tokens.
     * - ✅ Authenticate your apps (so you know who is talking to you).
     * - ❌ Use stricter rate-limiting for authentication, and implement lockout policies and weak password checks.
     */

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api2:2023-no-http-basic": {
      message:
        "Security scheme uses HTTP Basic. Use a more secure authentication method, like OAuth 2, or OpenID.",
      description:
        "Basic authentication credentials transported over network are more susceptible to interception than other forms of authentication, and as they are not encrypted it means passwords and tokens are more easily leaked.",
      severity: DiagnosticSeverity.Error,
      given: "$.components.securitySchemes[*]",
      then: {
        field: "scheme",
        function: pattern,
        functionOptions: {
          notMatch: "basic",
        },
      },
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/rules/secrets-parameters.yml
     */
    "owasp:api2:2023-no-api-keys-in-url": {
      message: "API Key passed in URL: {{error}}.",
      description:
        "API Keys are are passed in headers, cookies or query parameters to access APIs Those keys can be eavesdropped, especially when they are passed in the URL as logging or history tools will keep track of them and potentially expose them.",
      severity: DiagnosticSeverity.Error,
      formats: [oas3],
      given: ['$..[securitySchemes][?(@ && @.type=="apiKey")].in'],
      then: [
        {
          function: pattern,
          functionOptions: {
            notMatch: "^(path|query)$",
          },
        },
      ],
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/rules/secrets-parameters.yml
     */
    "owasp:api2:2023-no-credentials-in-url": {
      message: "Security credentials detected in path parameter: {{value}}.",
      description:
        "URL parameters MUST NOT contain credentials such as API key, password, or secret. See [RAC_GEN_004](https://docs.italia.it/italia/piano-triennale-ict/lg-modellointeroperabilita-docs/it/bozza/doc/04_Raccomandazioni%20di%20implementazione/04_raccomandazioni-tecniche-generali/01_globali.html?highlight=credenziali#rac-gen-004-non-passare-credenziali-o-dati-riservati-nellurl)",
      severity: DiagnosticSeverity.Error,
      formats: [oas3],
      given: ["$..parameters[?(@ && @.in && @.in.match(/query|path/))].name"],
      then: [
        {
          field: "name",
          function: pattern,
          functionOptions: {
            notMatch:
              "/^.*(client_?secret|token|access_?token|refresh_?token|id_?token|password|secret|api-?key).*$/i",
          },
        },
      ],
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/security/securitySchemes_insecure.yml#L38
     */
    "owasp:api2:2023-auth-insecure-schemes": {
      message:
        "Authentication scheme is considered outdated or insecure: {{value}}.",
      description:
        "There are many [HTTP authorization schemes](https://www.iana.org/assignments/http-authschemes/) but some of them are now considered insecure, such as negotiating authentication using specifications like NTLM or OAuth v1.",
      severity: DiagnosticSeverity.Error,
      formats: [oas3],
      given: ['$..[securitySchemes][?(@.type=="http")].scheme'],
      then: [
        {
          function: pattern,
          functionOptions: {
            notMatch: "^(negotiate|oauth)$",
          },
        },
      ],
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/security/securitySchemes.yml
     */
    "owasp:api2:2023-jwt-best-practices": {
      message:
        "Security schemes using JWTs must explicitly declare support for RFC8725 in the description.",
      description:
        'JSON Web Tokens RFC7519 is a compact, URL-safe, means of representing claims to be transferred between two parties. JWT can be enclosed in encrypted or signed tokens like JWS and JWE.\n\nThe [JOSE IANA registry](https://www.iana.org/assignments/jose/jose.xhtml) provides algorithms information.\n\nRFC8725 describes common pitfalls in the JWx specifications and in\ntheir implementations, such as:\n- the ability to ignore algorithms, eg. `{"alg": "none"}`;\n- using insecure algorithms like `RSASSA-PKCS1-v1_5` eg. `{"alg": "RS256"}`.\nAn API using JWT should explicit in the `description`\nthat the implementation conforms to RFC8725.\n```\ncomponents:\n  securitySchemes:\n    JWTBearer:\n      type: http\n      scheme: bearer\n      bearerFormat: JWT\n      description: |-\n        A bearer token in the format of a JWS and conformato\n        to the specifications included in RFC8725.\n```',
      severity: DiagnosticSeverity.Error,
      given: [
        '$.components.securitySchemes[?(@ && @.type=="oauth2")]',
        '$.components.securitySchemes[?(@ && (@.bearerFormat=="jwt" || @.bearerFormat=="JWT"))]',
      ],
      then: [
        {
          field: "description",
          function: truthy,
        },
        {
          field: "description",
          function: pattern,
          functionOptions: {
            match: ".*RFC8725.*",
          },
        },
      ],
    },

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api2:2023-short-lived-access-tokens": {
      message:
        "Authentication scheme does not appear to support refresh tokens, meaning access tokens likely do not expire.",
      description:
        "Using short-lived access tokens is a good practice, and when using OAuth 2 this is done by using refresh tokens. If a malicious actor is able to get hold of an access token then rotation means that token might not work by the time they try to use it, or it could at least reduce how long they are able to perform malicious requests.",
      severity: DiagnosticSeverity.Error,
      given: ['$.components.securitySchemes[?(@ && @.type=="oauth2")].flows.*'],
      then: [
        {
          field: "refreshUrl",
          function: truthy,
        },
      ],
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/security/security.yml
     */
    "owasp:api2:2023-write-restricted": {
      message: "This write operation is not protected by any security scheme.",
      description:
        "All write operations (POST, PUT, PATCH, DELETE) must be secured by at least one security scheme. Security schemes are defined in the `securityScheme` section then referenced in the `security` key at the global or operation levels.",
      severity: DiagnosticSeverity.Error,
      given: "$",
      then: [
        {
          function: checkSecurity,
          functionOptions: {
            schemesPath: ["securitySchemes"],
            methods: ["post", "put", "patch", "delete"],
          },
        },
      ],
    },

    "owasp:api2:2023-read-restricted": {
      message: "This read operation is not protected by any security scheme.",
      description:
        "Read operations (GET, HEAD) should be secured by at least one security scheme. Security schemes are defined in the `securityScheme` section then referenced in the `security` key at the global or operation levels.",
      severity: DiagnosticSeverity.Warning,
      given: "$",
      then: [
        {
          function: checkSecurity,
          functionOptions: {
            schemesPath: ["securitySchemes"],
            nullable: true,
            methods: ["get", "head"],
          },
        },
      ],
    },

    /**
     * API3:2023 Broken Object Property Level Authorization
     * https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
     *
     * Use case
     * - ❌ APIs expose endpoints that return all object’s properties.
     * - ❌ Unauthorized access to private/sensitive object properties may result in data disclosure, data loss, or data corruption. Under certain circumstances, unauthorized access to object properties can lead to privilege escalation or partial/full account takeover.
     * - 🟠 The API endpoint exposes properties of an object that are considered sensitive and should not be read by the user.
     * - ✅ The API endpoint allows a user to change, add/or delete the value of a sensitive object's property which the user should not be able to access
     *
     * How to prevent
     * - ✅ Carefully define schemas for all the API responses (restricting unknown properties)
     * - 🟠 Identify all the sensitive data or Personally Identifiable Information (PII), and justify its use.
     * https://github.com/stoplightio/spectral-owasp-ruleset/issues/11
     * - ❌ Enforce response checks to prevent accidental leaks of data or exceptions.
     */

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/security/objects.yml
     */
    "owasp:api3:2023-no-additionalProperties": {
      message:
        "If the additionalProperties keyword is used it must be set to false.",
      description:
        "By default JSON Schema allows additional properties, which can potentially lead to mass assignment issues, where unspecified fields are passed to the API without validation. Disable them with `additionalProperties: false` or add `maxProperties`.",
      severity: DiagnosticSeverity.Warning,
      formats: [oas3_0],
      given: '$..[?(@ && @.type=="object" && @.additionalProperties)]',
      then: [
        {
          field: "additionalProperties",
          function: falsy,
        },
      ],
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/security/objects.yml
     */
    "owasp:api3:2023-constrained-additionalProperties": {
      message: "Objects should not allow unconstrained additionalProperties.",
      description:
        "By default JSON Schema allows additional properties, which can potentially lead to mass assignment issues, where unspecified fields are passed to the API without validation. Disable them with `additionalProperties: false` or add `maxProperties`",
      severity: DiagnosticSeverity.Warning,
      formats: [oas3_0],
      given:
        '$..[?(@ && @.type=="object" && @.additionalProperties &&  @.additionalProperties!=true &&  @.additionalProperties!=false )]',
      then: [
        {
          field: "maxProperties",
          function: defined,
        },
      ],
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/security/objects.yml
     */
    "owasp:api3:2023-no-unevaluatedProperties": {
      message:
        "If the unevaluatedProperties keyword is used it must be set to false.",
      description:
        "By default JSON Schema allows unevaluated properties, which can potentially lead to mass assignment issues, where unspecified fields are passed to the API without validation. Disable them with `unevaluatedProperties: false` or add `maxProperties`.",
      severity: DiagnosticSeverity.Warning,
      formats: [oas3_1],
      given: '$..[?(@ && @.type=="object" && @.unevaluatedProperties)]',
      then: [
        {
          field: "unevaluatedProperties",
          function: falsy,
        },
      ],
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/security/objects.yml
     */
    "owasp:api3:2023-constrained-unevaluatedProperties": {
      message: "Objects should not allow unconstrained unevaluatedProperties.",
      description:
        "By default JSON Schema allows unevaluated properties, which can potentially lead to mass assignment issues, where unspecified fields are passed to the API without validation. Disable them with `unevaluatedProperties: false` or add `maxProperties`",
      severity: DiagnosticSeverity.Warning,
      formats: [oas3_1],
      given:
        '$..[?(@ && @.type=="object" && @.unevaluatedProperties &&  @.unevaluatedProperties!=true &&  @.unevaluatedProperties!=false )]',
      then: [
        {
          field: "maxProperties",
          function: defined,
        },
      ],
    },

    /**
     * API4:2023 - Unrestricted Resource Consumption
     * https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
     *
     * Use case
     * - ✅ Attackers overload the API by sending more requests than it can handle.
     * - ✅ Attackers send requests at a rate exceeding the API's processing speed, clogging it up.
     * - ✅ The size of the requests or some fields in them exceed what the API can process.
     * - 🟠 “Zip bombs”, archive files that have been designed so that unpacking them takes excessive amount of resources and overloads the API.
     *
     * How to prevent
     * - ✅ Define proper rate limiting.
     * - ✅ Limit maximums on request parameter sizes
     * - ❌ Tailor the rate limiting to be match what API methods, clients, or addresses need or should be allowed to get.
     * - ❌ Add checks on compression ratios.
     * - ❌ Define limits for container resources.
     * - 🟠 Look for Zip uploads and warn about setting max file size? how do we know if they did? Demand something in the description?
     */

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api4:2023-rate-limit": {
      message: "All 2XX and 4XX responses should define rate limiting headers.",
      description:
        "Define proper rate limiting to avoid attackers overloading the API. There are many ways to implement rate-limiting, but most of them involve using HTTP headers, and there are two popular ways to do that:\n\nIETF Draft HTTP RateLimit Headers:. https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/\n\nCustomer headers like X-Rate-Limit-Limit (Twitter: https://developer.twitter.com/en/docs/twitter-api/rate-limits) or X-RateLimit-Limit (GitHub: https://docs.github.com/en/rest/overview/resources-in-the-rest-api)",
      severity: DiagnosticSeverity.Error,
      formats: [oas3],
      given: "$.paths[*]..responses[?(@property.match(/^(2|4)/))]",
      then: {
        field: "headers",
        function: schema,
        functionOptions: {
          schema: {
            type: "object",
            oneOf: [
              {
                required: ["RateLimit"],
              },
              {
                required: ["RateLimit-Limit", "RateLimit-Reset"],
              },
              {
                required: ["X-RateLimit-Limit"],
              },
              {
                required: ["X-Rate-Limit-Limit"],
              },
            ],
          },
        },
      },
    },

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api4:2023-rate-limit-retry-after": {
      message: "A 429 response should define a Retry-After header.",
      description:
        "Define proper rate limiting to avoid attackers overloading the API. Part of that involves setting a Retry-After header so well meaning consumers are not polling and potentially exacerbating problems.",
      severity: DiagnosticSeverity.Error,
      formats: [oas3],
      given: "$..responses[429].headers",
      then: {
        field: "Retry-After",
        function: defined,
      },
    },

    /**
     * @author: Jason Harmon <https://github.com/jharmn>
     */
    "owasp:api4:2023-rate-limit-responses-429": {
      message: "Operation is missing rate limiting response in {{property}}.",
      description:
        "OWASP API Security recommends defining schemas for all responses, even errors. A HTTP 429 response signals the API client is making too many requests, and will supply information about when to retry so that the client can back off calmly without everything breaking. Defining this response is important not just for documentation, but to empower contract testing to make sure the proper JSON structure is being returned instead of leaking implementation details in backtraces. It also ensures your API/framework/gateway actually has rate limiting set up.",
      severity: DiagnosticSeverity.Warning,
      given: "$.paths..responses",
      then: [
        {
          field: "429",
          function: truthy,
        },
        {
          field: "429.content",
          function: truthy,
        },
      ],
    },

    /**
     * @author: Roberto Polli <https://github.com/ioggstream>
     * @see: https://github.com/italia/api-oas-checker/blob/master/security/array.yml
     */
    "owasp:api4:2023-array-limit": {
      message: "Schema of type array must specify maxItems.",
      description:
        "Array size should be limited to mitigate resource exhaustion attacks. This can be done using `maxItems`. You should ensure that the subschema in `items` is constrained too.",
      severity: DiagnosticSeverity.Error,
      given: "#ArrayProperties",
      then: {
        field: "maxItems",
        function: defined,
      },
    },

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api4:2023-string-limit": {
      message: "Schema of type string must specify maxLength, enum, or const.",
      description:
        "String size should be limited to mitigate resource exhaustion attacks. This can be done using `maxLength`, `enum` or `const`.",
      severity: DiagnosticSeverity.Error,
      given: "#StringProperties",
      then: {
        function: schema,
        functionOptions: {
          schema: {
            type: "object",
            anyOf: [
              {
                required: ["maxLength"],
              },
              {
                required: ["enum"],
              },
              {
                required: ["const"],
              },
            ],
          },
        },
      },
    },

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api4:2023-string-restricted": {
      message:
        "Schema of type string should specify a format, pattern, enum, or const.",
      description:
        "To avoid unexpected values being sent or leaked, strings should have a `format`, RegEx `pattern`, `enum`, or `const`.",
      severity: DiagnosticSeverity.Warning,
      given: "#StringProperties",
      then: {
        function: schema,
        functionOptions: {
          schema: {
            type: "object",
            anyOf: [
              {
                required: ["format"],
              },
              {
                required: ["pattern"],
              },
              {
                required: ["enum"],
              },
              {
                required: ["const"],
              },
            ],
          },
        },
      },
    },

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api4:2023-integer-limit": {
      message: "Schema of type integer must specify minimum and maximum.",
      description:
        "Integers should be limited to mitigate resource exhaustion attacks. This can be done using `minimum` and `maximum`, which can with e.g.: avoiding negative numbers when positive are expected, or reducing unreasonable iterations like doing something 1000 times when 10 is expected.",
      severity: DiagnosticSeverity.Error,
      formats: [oas3_1],
      given: "#IntegerProperties",
      then: [
        {
          function: xor,
          functionOptions: {
            properties: ["minimum", "exclusiveMinimum"],
          },
        },
        {
          function: xor,
          functionOptions: {
            properties: ["maximum", "exclusiveMaximum"],
          },
        },
      ],
    },

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api4:2023-integer-limit-legacy": {
      message: "Schema of type integer must specify minimum and maximum.",
      description:
        "Integers should be limited to mitigate resource exhaustion attacks. This can be done using `minimum` and `maximum`, which can with e.g.: avoiding negative numbers when positive are expected, or reducing unreasonable iterations like doing something 1000 times when 10 is expected.",
      severity: DiagnosticSeverity.Error,
      formats: [oas2, oas3_0],
      given: "#IntegerProperties",
      then: [
        {
          field: "minimum",
          function: defined,
        },
        {
          field: "maximum",
          function: defined,
        },
      ],
    },

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api4:2023-integer-format": {
      message: "Schema of type integer must specify format (int32 or int64).",
      description:
        "Integers should be limited to mitigate resource exhaustion attacks. Specifying whether int32 or int64 is expected via `format`.",
      severity: DiagnosticSeverity.Error,
      given: "#IntegerProperties",
      then: [
        {
          field: "format",
          function: defined,
        },
      ],
    },

    /**
     * API5:2023 — Broken function level authorization
     * https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
     *
     * - ✅ Don’t assume that an API endpoint is regular or administrative only based on the URL path.
     * - ❌ Do not rely on the client to enforce admin access.
     * - ✅ Deny all access by default api2:2023-protection-
     */

    "owasp:api5:2023-admin-security-unique": {
      message: "{{error}}",
      description: "",
      severity: DiagnosticSeverity.Error,
      given: "$",
      then: [
        {
          function: differentSecuritySchemes,
          functionOptions: {
            adminUrl: "/admin",
          },
        },
      ],
    },

    /**
     * API6:2023 - Unrestricted Access to Sensitive Business Flows
     * https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
     *
     * Use case
     *
     * - ❌ Purchasing a product flow - an attacker can buy all the stock of a
     *   high-demand item at once and resell for a higher price (scalping)
     * - ❌ Creating a comment/post flow - an attacker can spam the system
     * - ❌ Making a reservation - an attacker can reserve all the available time
     *   slots and prevent other users from using the system
     *
     * How to prevent
     *
     * - Device fingerprinting: denying service to unexpected client devices
     *   (e.g headless browsers) tends to make threat actors use more
     *   sophisticated solutions, thus more costly for them
     * - Human detection: using either captcha or more advanced biometric
     *   solutions (e.g. typing patterns)
     * - Non-human patterns: analyze the user flow to detect non-human patterns
     *   (e.g. the user accessed the "add to cart" and "complete purchase"
     *   functions in less than one second)
     * - Consider blocking IP addresses of Tor exit nodes and well-known proxies
     */

    /**
     * API7:2023 — Server Side Request Forgery
     * https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/
     *
     * Modern concepts encourage developers to access an external resource based
     * on user input: Webhooks, file fetching from URLs, custom SSO, and URL
     * previews.
     *
     */

    "owasp:api7:2023-concerning-url-parameter": {
      message:
        "Make sure to review the way this URL is handled to protect against Server Side Request Forgery.",
      description:
        "Using external resource based on user input for webhooks, file fetching from URLs, custom SSO, URL previews, or redirects, can lead to a wide variety of security issues.\n\nLearn more about Server Side Request Forgery here: https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
      severity: DiagnosticSeverity.Information,
      given: [
          '$.paths[*].parameters[*].name',
          '$.paths[*][get,put,post,delete,options,head,patch,trace].parameters[*].name',
        ],
      then: {
        function: pattern,
        functionOptions: {
          notMatch: /(^(callback|redirect)|(_url|Url|-url))$/,
        }
      },
    },

    /**
     * API8:2023 — Security Misconfiguration
     * https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
     *
     * Poor configuration of the API servers allows attackers to exploit them.
     *
     * Use case
     * - ❌ Unpatched systems
     * - ❌ Unprotected files and directories
     * - ❌ Unhardened images
     * - ✅ Missing, outdated, or misconfigured TLS
     * - ❌ Exposed storage or server management panels
     * - ✅ Missing CORS policy or security headers
     * - 🟠 Error messages with stack traces
     * https://github.com/stoplightio/spectral-owasp-ruleset/issues/12
     * - ❌ Unnecessary features enabled
     *
     */

    /**
     * @author: Phil Sturgeon (https://github.com/philsturgeon)
     */
    "owasp:api8:2023-define-cors-origin": {
      message: "Header `{{property}}` should be defined on all responses.",
      description:
        'Setting up CORS headers will control which websites can make browser-based HTTP requests to your API, using either the wildcard "*" to allow any origin, or "null" to disable any origin. Alternatively you can use "Access-Control-Allow-Origin: https://example.com" to indicate that only requests originating from the specified domain (https://example.com) are allowed to access its resources.\n\nMore about CORS here: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS.',
      given: "$..headers",
      then: {
        field: "Access-Control-Allow-Origin",
        function: truthy,
      },
      severity: DiagnosticSeverity.Error,
    },

    /**
     * @author: Andrzej <https://github.com/jerzyn>
     */
    "owasp:api8:2023-no-scheme-http": {
      message: "Server schemes must not use http. Use https or wss instead.",
      description:
        "Server interactions must use the http protocol as it's inherently insecure and can lead to PII and other sensitive information being leaked through traffic sniffing or man-in-the-middle attacks. Use the https or wss schemes instead.\n\nLearn more about the importance of TLS (over SSL) here: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
      severity: DiagnosticSeverity.Error,
      formats: [oas2],
      given: "$.schemes.*",
      then: {
        function: schema,
        functionOptions: {
          schema: {
            type: "string",
            enum: ["https", "wss"],
          },
        },
      },
    },

    /**
     * @author: Andrzej <https://github.com/jerzyn>
     */
    "owasp:api8:2023-no-server-http": {
      message:
        "Server URLs must not use http://. Use https:// or wss:// instead.",
      description:
        "Server interactions must not use the http:// as it's inherently insecure and can lead to PII and other sensitive information being leaked through traffic sniffing or man-in-the-middle attacks. Use https:// or wss:// protocols instead.\n\nLearn more about the importance of TLS (over SSL) here: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
      severity: DiagnosticSeverity.Error,
      formats: [oas3],
      given: "$.servers..url",
      then: {
        function: pattern,
        functionOptions: {
          notMatch: "/^http:/",
        },
      },
    },

    /**
     * @author: Jason Harmon <https://github.com/jharmn>
     */
    "owasp:api8:2023-define-error-validation": {
      message: "Missing error response of either 400, 422 or 4XX.",
      description:
        "Carefully define schemas for all the API responses, including either 400, 422 or 4XX responses which describe errors caused by invalid requests.",
      severity: DiagnosticSeverity.Warning,
      given: "$.paths..responses",
      then: [
        {
          function: schema,
          functionOptions: {
            schema: {
              type: "object",
              anyOf: [
                {
                  required: ["400"],
                },
                {
                  required: ["422"],
                },
                {
                  required: ["4XX"],
                },
              ],
            },
          },
        },
      ],
    },

    /**
     * @author: Jason Harmon <https://github.com/jharmn>
     */
    "owasp:api8:2023-define-error-responses-401": {
      message: "Operation is missing {{property}}.",
      description:
        "OWASP API Security recommends defining schemas for all responses, even errors. The 401 describes what happens when a request is unauthorized, so its important to define this not just for documentation, but to empower contract testing to make sure the proper JSON structure is being returned instead of leaking implementation details in backtraces.",
      severity: DiagnosticSeverity.Warning,
      given: "$.paths..responses",
      then: [
        {
          field: "401",
          function: truthy,
        },
        {
          field: "401.content",
          function: truthy,
        },
      ],
    },

    /**
     * @author: Jason Harmon <https://github.com/jharmn>
     */
    "owasp:api8:2023-define-error-responses-500": {
      message: "Operation is missing {{property}}.",
      description:
        "OWASP API Security recommends defining schemas for all responses, even errors. The 500 describes what happens when a request fails with an internal server error, so its important to define this not just for documentation, but to empower contract testing to make sure the proper JSON structure is being returned instead of leaking implementation details in backtraces.",
      severity: DiagnosticSeverity.Warning,
      given: "$.paths..responses",
      then: [
        {
          field: "500",
          function: truthy,
        },
        {
          field: "500.content",
          function: truthy,
        },
      ],
    },

    /**
     * API9:2023 Improper Inventory Management
     * https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/
     *
     * How to prevent
     * - 🟠 Servers, define which environment is the API running in (e.g. production, staging, test, development)
     * - ✅ Require servers use x-internal true/false to explicitly explain what is public or internal for documentation tools
     * - 🤷‍♂️ There is no retirement plan for each API version.
     */

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api9:2023-inventory-access": {
      message:
        "Declare intended audience of every server by defining servers{{property}} as true/false.",
      description:
        "Servers are required to use vendor extension x-internal set to true or false to explicitly explain the audience for the API, which will be picked up by most documentation tools.",
      severity: DiagnosticSeverity.Error,
      formats: [oas3],
      given: "$.servers.*",
      then: {
        field: "x-internal",
        function: defined,
      },
    },

    /**
     * @author: Phil Sturgeon <https://github.com/philsturgeon>
     */
    "owasp:api9:2023-inventory-environment": {
      message:
        "Declare intended environment in server descriptions using terms like local, staging, production.",
      description:
        "Make it clear which servers are expected to run as which environment to avoid unexpected problems, exposing test data to the public, or letting bad actors bypass security measures to get to production-like environments.",
      severity: DiagnosticSeverity.Error,
      formats: [oas3],
      given: "$.servers.*",
      then: {
        field: "description",
        function: pattern,
        functionOptions: {
          match:
            "/(local|sandbox|alpha|beta|test|testing|stag|staging|prod|production|next|preprod|preproduction)/i",
        },
      },
    },

    /**
     * API10:2023 Unsafe Consumption of APIs
     * https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/
     *
     * Use case
     * - ❌ Interacts with other APIs over an unencrypted channel;
     * - ❌ Does not properly validate and sanitize data gathered from other APIs prior to processing it or passing it to downstream components;
     * - ✅ Blindly follows redirections;
     * - ❌ Does not limit the number of resources available to process third-party services responses;
     * - ❌ Does not implement timeouts for interactions with third-party services;
     */
  },
};
