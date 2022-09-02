import { pattern, schema } from "@stoplight/spectral-functions";
import { oas2, oas3 } from "@stoplight/spectral-formats";
import { DiagnosticSeverity } from "@stoplight/types";

export default {
  rules: {
    /**
     * API1:2019 - Broken Object Level Authorization
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

    // Author: Phil Sturgeon (https://github.com/philsturgeon)
    "owasp:api1:2019-no-numeric-ids": {
      description:
        "OWASP API1:2019 - Use random IDs that cannot be guessed (UUIDs)",
      given:
        '$.paths..parameters[*].[?(@property === "name" && (@ === "id" || @.match(/(_id|Id)$/)))]^.schema',
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
            properties: {
              format: {
                const: "uuid",
              },
            },
          },
        },
      },
      severity: DiagnosticSeverity.Error,
    },

    /**
     * API2:2019 — Broken authentication
     *
     * Use case
     * - 🟠 Unprotected APIs that are considered “internal”
     * - ✅ Weak authentication that does not follow industry best practices
     * - 🟠 Weak API keys that are not rotated
     * - ❌ Passwords that are weak, plain text, encrypted, poorly hashed, shared, or default passwords
     * - 🤷 Authentication susceptible to brute force attacks and credential stuffing
     * - ✅ Credentials and keys included in URLs
     * - 🟠 Lack of access token validation (including JWT validation)
     * 👆 https://github.com/italia/api-oas-checker/blob/master/security/securitySchemes.yml#L3
     * - 🟠 Unsigned or weakly signed non-expiring JWTs
     * 👆 https://github.com/italia/api-oas-checker/blob/master/security/securitySchemes.yml#L44
     *
     * How to prevent
     * - ❌ APIs for password reset and one-time links also allow users to authenticate, and should be protected just as rigorously.
     * - ✅ Use standard authentication, token generation, password storage, and multi-factor authentication (MFA).
     * - ❌ Use short-lived access tokens.
     * - 🟠 Authenticate your apps (so you know who is talking to you).
     *   👆 https://github.com/italia/api-oas-checker/blob/master/security/security.yml
     * - ❌ Use stricter rate-limiting for authentication, and implement lockout policies and weak password checks.
     */

    // Author: Phil Sturgeon (https://github.com/philsturgeon)
    "owasp:api2:2019-no-http-basic": {
      description: "Basic authentication credentials transported over network",
      message:
        "{{property}} uses basic auth. Use a more secure authentication method, like OAuth 2.0.",
      given: "$.components.securitySchemes[*]",
      then: {
        field: "scheme",
        function: pattern,
        functionOptions: {
          notMatch: "basic",
        },
      },
      severity: DiagnosticSeverity.Error,
    },

    // Author: Roberto Polli (github.com/ioggstream)
    // https://github.com/italia/api-oas-checker/blob/master/rules/secrets-parameters.yml
    "api2:2019-no-api-keys-in-url": {
      description:
        "API Keys are (usually opaque) strings that\nare passed in headers, cookies or query parameters\nto access APIs.\nThose keys can be eavesdropped, especially when they are stored\nin cookies or passed as URL parameters.\n```\nsecurity:\n- ApiKey: []\npaths:\n  /books: {}\n  /users: {}\nsecuritySchemes:\n  ApiKey:\n    type: apiKey\n    in: cookie\n    name: X-Api-Key\n```",
      message: "ApiKey passed in URL: {{error}}.",
      formats: ["oas3"],
      severity: "error",
      recommended: true,
      given: ['$..[securitySchemes][?(@ && @.type=="apiKey")].in'],
      then: [
        {
          function: "pattern",
          functionOptions: {
            notMatch: "^(query)$",
          },
        },
      ],
    },

    // Author: Roberto Polli (github.com/ioggstream)
    // https://github.com/italia/api-oas-checker/blob/master/rules/secrets-parameters.yml
    "owasp:api2:2019-no-credentials-in-url": {
      description:
        "URL parameters MUST NOT contain credentials such as\napikey, password, or secret.\nSee [RAC_GEN_004](https://docs.italia.it/italia/piano-triennale-ict/lg-modellointeroperabilita-docs/it/bozza/doc/04_Raccomandazioni%20di%20implementazione/04_raccomandazioni-tecniche-generali/01_globali.html?highlight=credenziali#rac-gen-004-non-passare-credenziali-o-dati-riservati-nellurl)",
      message: "Credentials are sent via URLs. {{path}} {{error}}",
      formats: ["oas3"],
      severity: "error",
      recommended: true,
      given: ["$..parameters[?(@ && @.in && @.in.match(/query|path/))].name"],
      then: [
        {
          field: "name",
          function: "pattern",
          functionOptions: {
            notMatch: "/^.*(password|secret|apikey).*$/i",
          },
        },
      ],
    },

    // Author: Roberto Polli (github.com/ioggstream)
    // https://github.com/italia/api-oas-checker/blob/master/security/securitySchemes_insecure.yml#L38
    "owasp:api2:2019-auth-insecure-schemes": {
      description:
        "The HTTP authorization type in OAS supports\nall the schemes defined in the associated\n[IANA table](https://www.iana.org/assignments/http-authschemes/).\nSome of those schemes are\nnow considered insecure, such as\nnegotiating authentication using specifications\nlike NTLM or OAuth v1.",
      message: "Authentication scheme is insecure: {{error}}",
      formats: ["oas3"],
      recommended: true,
      severity: "error",
      given: ['$..[securitySchemes][?(@.type=="http")].scheme'],
      then: [
        {
          function: "pattern",
          functionOptions: {
            notMatch: "^(negotiate|oauth)$",
          },
        },
      ],
    },

    /**
     * API3:2019 — Excessive data exposure
     *
     * Use case
     * - ❌ The API returns full data objects as they are stored in the backend database.
     * - ❌ The client application filters the responses and only shows the data that the users really need to see.
     * - ❌ Attackers call the API directly and get also the sensitive data that the UI would filter out.
     *
     * How to prevent
     * - ❌ Never rely on the client to filter data!
     * - ❌ Review all API responses and adapt them to match what the API consumers really need.
     * - ❌ Carefully define schemas for all the API responses.
     * - ✅ Do not forget about error responses, define proper schemas as well.
     * - 🟠 Identify all the sensitive data or Personally Identifiable Information (PII), and justify its use.
     * - ❌ Enforce response checks to prevent accidental leaks of data or exceptions.
     */

    // Author: Jason Harmon (github.com/jharmn)
    "owasp:api3:2019-define-error-responses-400": {
      description: "400 response should be defined.",
      message: "{{description}}. Missing {{property}}",
      severity: "warning",
      given: "$.paths..responses",
      then: [
        {
          field: "400",
          function: "truthy",
        },
      ],
    },
 
    // Author: Jason Harmon (github.com/jharmn)
    "owasp:api3:2019-define-error-responses-429": {
      description: "429 response should be defined.",
      message: "{{description}}. Missing {{property}}",
      severity: "warning",
      given: "$.paths..responses",
      then: [
        {
          field: "429",
          function: "truthy",
        },
      ],
    },
    
    // Author: Jason Harmon (github.com/jharmn)
    "owasp:api3:2019-define-error-responses-500": {
      description: "500 response should be defined.",
      message: "{{description}}. Missing {{property}}",
      severity: "warning",
      given: "$.paths..responses",
      then: [
        {
          field: "500",
          function: "truthy",
        },
      ],
    },
    
    /**
     * API4:2019 — Lack of resources and rate limiting
     *
     * Use case
     * - 🟠 Attackers overload the API by sending more requests than it can handle.
     * - ❌ Attackers send requests at a rate exceeding the API's processing speed, clogging it up.
     * - ❌ The size of the requests or some fields in them exceed what the API can process.
     * - 🟠 “Zip bombs”, archive files that have been designed so that unpacking them takes excessive amount of resources and overloads the API.
     *
     * How to prevent
     * - 🟠 Define proper rate limiting.
     * - ❌ Limit payload sizes.
     * - ❌ Tailor the rate limiting to be match what API methods, clients, or addresses need or should be allowed to get.
     * - ❌ Add checks on compression ratios.
     * - ❌ Define limits for container resources.
     * - 🟠 PS: Look for Zip uploads and warn about setting max file size? how do we know if they did? Demand something in the description?
     * - 🟠 PS: Limit array sizes
     * 👆 https://github.com/italia/api-oas-checker/blob/master/security/array.yml
     */

    /**
     * API5:2019 — Broken function level authorization
     *
     * - Do not rely on the client to enforce admin access.
     * - Deny all access by default.
     * - Only allow operations to users belonging to the appropriate group or role.
     * - Properly design and test authorization.
     */

    // 'owasp:api5:2019-broken-function-level-authorization':
    // 'https://apisecurity.io/encyclopedia/content/owasp/api5-broken-function-level-authorization',

    /**
     * API6:2019 — Mass assignment
     *
     * The API takes data that client provides and stores it without proper filtering for whitelisted properties. Attackers can try to guess object properties or provide additional object properties in their requests, read the documentation, or check out API endpoints for clues where to find the openings to modify properties they are not supposed to on the data objects stored in the backend.
     *
     * Use case
     *
     * - ❌ The API works with the data structures without proper filtering.
     * - ❌ Received payload is blindly transformed into an object and stored.
     * - ❌ Attackers can guess the fields by looking at the GET request data.
     *
     * How to prevent
     * - ❌ Do not automatically bind incoming data and internal objects.
     * - 🟠 Explicitly define all the parameters and payloads you are expecting.
     * 👆 https://github.com/italia/api-oas-checker/blob/master/security/objects.yml#L2
     * - 🟠 Use the readOnly property set to true in object schemas for all properties that can be retrieved through APIs but should never be modified.
     * - 🟠 Precisely define the schemas, types, and patterns you will accept in requests at design time and enforce them at runtime.
     */

    // 'owasp:api6:2019-mass-assignment':
    // 'https://apisecurity.io/encyclopedia/content/owasp/api6-mass-assignment',

    /**
     * API7:2019 — Security misconfiguration
     *
     * Poor configuration of the API servers allows attackers to exploit them.
     *
     * Use case
     * - ❌ Unpatched systems
     * - ❌ Unprotected files and directories
     * - ❌ Unhardened images
     * - 🟠 Missing, outdated, or misconfigured TLS
     * - ❌ Exposed storage or server management panels
     * - 🟠 Missing CORS policy or security headers
     * - 🟠 Error messages with stack traces
     * - ❌ Unnecessary features enabled
     *
     * How to prevent
     * - ❌ Establish repeatable hardening and patching processes.
     * - ❌ Automate locating configuration flaws.
     * - ❌ Disable unnecessary features.
     * - ❌ Restrict administrative access.
     * - 🟠 Define and enforce all outputs, including errors.
     */

    // Author: Andrzej (https://github.com/jerzyn)
    "owasp:api7:2019-security-hosts-https-oas2": {
      description: "ALL requests MUST go through `https` protocol only",
      message:
        "{{property}} uses http. Schemes MUST be https and no other value is allowed.",
      given: "$.schemes",
      then: {
        function: schema,
        functionOptions: {
          schema: {
            type: "array",
            items: {
              type: "string",
              const: "https",
            },
          },
        },
      },
      severity: DiagnosticSeverity.Error,
      formats: [oas2],
    },

    // Author: Andrzej (https://github.com/jerzyn)
    "owasp:api7:2019-security-hosts-https-oas3": {
      description: "ALL requests MUST go through https:// protocol only",
      message:
        "{{property}} uses http. Schemes MUST be https and no other value is allowed.",
      given: "$.servers..url",
      then: {
        function: pattern,
        functionOptions: {
          match: "/^https:/",
        },
      },
      formats: [oas3],
      severity: DiagnosticSeverity.Error,
    },

    /**
     * API8:2019 — Injection
     *
     * Attackers construct API calls that include SQL, NoSQL, LDAP, OS, or other commands that the API or the backend behind it blindly executes.
     *
     * Use cases
     * - 🟠 Attackers send malicious input to be forwarded to an internal interpreter:
     *   SQL
     *   NoSQL
     *   LDAP
     *   OS commands
     *   XML parsers
     *   Object-Relational Mapping (ORM)
     *
     * How to prevent
     * - 🟠 Never trust your API consumers, even if they are internal.
     * - 🟠 Strictly define all input data, such as schemas, types, and string patterns, and enforce them at runtime.
     * - ❌ Validate, filter, and sanitize all incoming data.
     * - 🟠 Define, limit, and enforce API outputs to prevent data leaks.
     */

    // 'owasp:api8:2019-injection':
    // 'https://apisecurity.io/encyclopedia/content/owasp/api8-injection',

    /**
     * API9:2019 — Improper assets management
     *
     * Attackers find non-production versions of the API (for example, staging, testing, beta, or earlier versions) that are not as well protected as the production API, and use those to launch their attacks.
     *
     * Use case
     * - ❌ DevOps, the cloud, containers, and Kubernetes make having multiple deployments easy (for example, dev, test, branches, staging, old versions).
     * - ❌ Desire to maintain backward compatibility forces to leave old APIs running.
     * - 🟠 Old or non-production versions are not properly maintained, but these endpoints still have access to production data.
     * - ❌ Once authenticated with one endpoint, attackers may switch to the other, production one.
     *
     * How to prevent
     * - ❌ Keep an up-to-date inventory all API hosts.
     * - ❌ Limit access to anything that should not be public.
     * - ❌ Limit access to production data, and segregate access to production and non-production data.
     * - ❌ Implement additional external controls, such as API firewalls.
     * - 🟠 Properly retire old versions of APIs or backport security fixes to them.
     * - 🟠 Implement strict authentication, redirects, CORS, and so forth.
     */

    // 'owasp:api9:2019-improper-assets-management':
    // 'https://apisecurity.io/encyclopedia/content/owasp/api9-improper-assets-management',

    /**
     * API10:2019 — Insufficient logging and monitoring
     *
     * Use case
     * - ❌ Logs are not protected for integrity.
     * - ❌ Logs are not integrated into Security Information and Event Management (SIEM) systems.
     * - ❌ Logs and alerts are poorly designed.
     * - ❌ Companies rely on manual rather than automated systems.
     *
     * How to prevent
     * - ❌ Log failed attempts, denied access, input validation failures, or any failures in security policy checks.
     * - ❌ Ensure that logs are formatted so that other tools can consume them as well.
     * - ❌ Protect logs like highly sensitive information.
     * - ❌ Include enough detail to identify attackers.
     * - ❌ Avoid having sensitive data in logs — if you need the information for debugging purposes, redact it partially.
     * - ❌ Integrate with SIEMs and other dashboards, monitoring, and alerting tools.
     */
  },
};
