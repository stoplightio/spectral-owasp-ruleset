# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-01-23

### Added

- Added `owasp:api2:2023-short-lived-access-tokens` to error on OAuth 2.x flows which do not use a refresh token.
- Added `owasp:api3:2023-no-unevaluatedProperties` (format `oas3_1` only.)
- Added `owasp:api3:2023-constrained-unevaluatedProperties` (format `oas3_1` only.)
- Added `owasp:api5:2023-admin-security-unique`.
- Added `owasp:api7:2023-concerning-url-parameter` to keep an eye out for URLs being passed as parameters and warn about server-side request forgery.
- Added `owasp:api8:2023-no-server-http` which supports `servers` having a `url` which is a relative path.
- Added `owasp:api9:2023-inventory-access` to indicate intended audience of every server.
- Added `owasp:api9:2023-inventory-environment` to declare intended environment for every server.

### Changed

- Deleted `owasp:api2:2023-protection-global-unsafe` as it allowed for unprotected POST, PATCH, PUT, DELETE and that's always going to be an issue. Use the new `owasp:api2:2023-write-restricted` rule which does not allow these operations to ever disable security, or use [Spectral overrides](https://docs.stoplight.io/docs/spectral/e5b9616d6d50c-rulesets) if you have an edge case.
- Renamed `owasp:api2:2019-protection-global-unsafe-strict` to `owasp:api2:2023-write-restricted`.
- Renamed `owasp:api2:2019-protection-global-safe` to `owasp:api2:2023-read-restricted` and increased severity from `info` to `warn`.
- Renamed `owasp:api2:2019-auth-insecure-schemes` to `owasp:api2:2023-auth-insecure-schemes`.
- Renamed `owasp:api2:2019-jwt-best-practices` to `owasp:api2:2023-jwt-best-practices`.
- Renamed `owasp:api2:2019-no-api-keys-in-url` to `owasp:api2:2023-no-api-keys-in-url`.
- Renamed `owasp:api2:2019-no-credentials-in-url` to `owasp:api2:2023-no-credentials-in-url`.
- Renamed `owasp:api2:2019-no-http-basic` to `owasp:api2:2023-no-http-basic`.
- Renamed `owasp:api3:2019-define-error-validation` to `owasp:api8:2023-define-error-validation`.
- Renamed `owasp:api3:2019-define-error-responses-401` to `owasp:api8:2023-define-error-responses-401`.
- Renamed `owasp:api3:2019-define-error-responses-500` to `owasp:api8:2023-define-error-responses-500`.
- Renamed `owasp:api4:2019-rate-limit` to `owasp:api4:2023-rate-limit` and added support for the singular `RateLimit` header in draft-ietf-httpapi-ratelimit-headers-07.
- Renamed `owasp:api4:2019-rate-limit-retry-after` to `owasp:api4:2023-rate-limit-retry-after`.
- Renamed `owasp:api4:2019-rate-limit-responses-429` to `owasp:api4:2023-rate-limit-responses-429`.
- Renamed `owasp:api4:2019-array-limit` to `owasp:api4:2023-array-limit`.
- Renamed `owasp:api4:2019-string-limit` to `owasp:api4:2023-string-limit`.
- Renamed `owasp:api4:2019-string-restricted` to `owasp:api4:2023-string-restricted` and downgraded from `error` to `warn`.
- Renamed `owasp:api4:2019-integer-limit` to `owasp:api4:2023-integer-limit`.
- Renamed `owasp:api4:2019-integer-limit-legacy` to `owasp:api4:2023-integer-limit-legacy`.
- Renamed `owasp:api4:2019-integer-format` to `owasp:api4:2023-integer-format`.
- Renamed `owasp:api6:2019-no-additionalProperties` to `owasp:api3:2023-no-additionalProperties` and restricted rule to only run the `oas3_0` format.
- Renamed `owasp:api6:2019-constrained-additionalProperties` to `owasp:api3:2023-constrained-additionalProperties`  and restricted rule to only run the `oas3_0` format.
- Renamed `owasp:api7:2023-security-hosts-https-oas2` to `owasp:api8:2023-no-scheme-http`.
- Renamed `owasp:api7:2023-security-hosts-https-oas3` to `owasp:api8:2023-no-server-http`.

### Removed

- Deleted `owasp:api2:2023-protection-global-unsafe` as it allowed for unprotected POST, PATCH, PUT, DELETE and that's always going to be an issue. Use the new `owasp:api2:2023-write-restricted` rule which does not allow these operations to ever disable security, or use [Spectral overrides](https://docs.stoplight.io/docs/spectral/e5b9616d6d50c-rulesets) if you have an edge case.
