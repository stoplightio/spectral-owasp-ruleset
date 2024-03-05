# Spectral OWASP API Security

[![NPM Downloads](https://img.shields.io/npm/dw/@stoplight/spectral-owasp-ruleset?color=blue)](https://www.npmjs.com/package/@stoplight/spectral-owasp-ruleset) [![Stoplight Forest](https://img.shields.io/ecologi/trees/stoplightinc)][stoplight_forest]

Scan an [OpenAPI](https://spec.openapis.org/oas/v3.1.0) document to detect security issues. As OpenAPI is only describing the surface level of the API it cannot see what is happening in your code, but it can spot obvious issues and outdated standards being used.

v2.x of this ruleset is based on the [OWASP API Security Top 10 2023 edition](https://owasp.org/API-Security/editions/2023/en/0x00-header/), but if you would like to use the [2019 edition](https://owasp.org/API-Security/editions/2019/en/0x00-header/) please use v1.x.

## Installation

```bash
npm install --save -D @stoplight/spectral-owasp-ruleset@^2.0
npm install --save -D @stoplight/spectral-cli
```

## Usage

Create a local ruleset that extends the ruleset. In its most basic form this just tells Spectral what ruleset you want to use, but it will allow you to customise things, add your own rules, turn bits off if its causing trouble.

```
cd ~/src/<your-api>

echo 'extends: ["@stoplight/spectral-owasp-ruleset"]' > .spectral.yaml
```

_If you're using VS Code or Stoplight Studio then the NPM modules will not be available. Instead you can use the CDN hosted version:_

```
echo 'extends: ["https://unpkg.com/@stoplight/spectral-owasp-ruleset/dist/ruleset.mjs"]' > .spectral.yaml
```

_**Note:** You need to use the full URL with CDN hosted rulesets because Spectral [cannot follow redirects through extends](https://github.com/stoplightio/spectral/issues/2266)._

Next, use Spectral CLI to lint against your OpenAPI description. Don't have any OpenAPI? [Record some HTTP traffic to make OpenAPI](https://apisyouwonthate.com/blog/creating-openapi-from-http-traffic) and then you can switch to API Design-First going forwards.

```
spectral lint api/openapi.yaml
```

You should see some output like this:

```
/Users/phil/src/protect-earth-api/api/openapi.yaml
  4:5        error    owasp:api8:2023-inventory-access            Declare intended audience of every server by defining servers[0].x-internal as true/false.  servers[0]
  4:10       error    owasp:api8:2023-no-server-http              Server URLs must not use http://. https:// is highly recommended.                        servers[0].url
  45:15        error  owasp:api4:2023-rate-limit                  All 2XX and 4XX responses should define rate limiting headers.  paths./upload.post.responses[201]
  47:15        error  owasp:api4:2023-rate-limit                  All 2XX and 4XX responses should define rate limiting headers.  paths./upload.post.responses[401]
  93:16  information  owasp:api2:2023-read-restricted             This operation is not protected by any security scheme.  paths./sites.get.security
 210:16  information  owasp:api2:2023-read-restricted             This operation is not protected by any security scheme.  paths./species.get.security
```

Now you have some things to work on for your API. Thankfully these are only at the `warning` and `information` severity, and that is not going to [fail continuous integration](https://docs.stoplight.io/docs/spectral/ZG9jOjExNTMyOTAx-continuous-integration) (unless [you want them to](https://docs.stoplight.io/docs/spectral/ZG9jOjI1MTg1-spectral-cli#error-results)).

There are [a bunch of other rulesets](https://github.com/stoplightio/spectral-rulesets) or [Stoplight API Stylebook](http://apistylebook.stoplight.io) you can use, or use for inspiration for your own rulesets and API Style Guides.

## 🎉 Thanks

- [Andrzej](https://github.com/jerzyn) - Great rules contributed to the Adidas style guide.
- [Roberto Polli](https://github.com/ioggstream) - Created lots of excellent Spectral rules for [API OAS Checker](https://github.com/italia/api-oas-checker/) which aligned with the OWASP API rules.

## 📜 License

This repository is licensed under the MIT license.

## 🌲 Sponsor

If you would like to thank us for creating Spectral, we ask that you [**buy the world a tree**][stoplight_forest].

[stoplight_forest]: https://ecologi.com/stoplightinc
