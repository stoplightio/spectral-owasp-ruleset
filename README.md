# APIs You Won't Hate: API Style Guide

Make your APIs "better" according to APIs You Won't Hate, with this slick command line tool that'll run on your [OpenAPI](https://spec.openapis.org/oas/v3.1.0). 

## Installation

``` bash
npm install --save -D @philsturgeon/spectral-owasp-ruleset
npm install --save -D @stoplight/spectral-cli
```

## Usage


Create a local ruleset that extends the style guide. In its most basic form this just tells Spectral what ruleset you want to use, but it will allow you to customise things, add your own rules, turn bits off if its causing trouble.

```
cd ~/src/<your-api>

echo 'extends: ["@philsturgeon/spectral-owasp-ruleset"]' > .spectral.yaml
```

_If you're using VS Code or Stoplight Studio then the NPM modules will not be available. Instead you can use the CDN hosted version:_

```
echo 'extends: ["https://unpkg.com/@philsturgeon/spectral-owasp-ruleset@1.0/dist/ruleset.js"]' > .spectral.yaml
```

Next, use Spectral CLI to lint against your OpenAPI description. Don't have any OpenAPI? [Record some HTTP traffic to make OpenAPI](https://apisyouwonthate.com/blog/creating-openapi-from-http-traffic) and then you can switch to API Design-First going forwards.

```
spectral lint api/openapi.yaml
```

You should see some output like this, letting you know there are a few more standards you could be using (shoutout to [Standards.REST](https://standards.rest/)):

```
/Users/phil/src/protect-earth-api/api/openapi.yaml
  18:7   warning  api-health               Creating a `/health` endpoint is a simple solution for pull-based monitoring and manually checking the status of an API.  paths
  18:7   warning  api-home                 Stop forcing all API consumers to visit documentation for basic interactions when the API could do that itself.           paths
  36:30  warning  no-unknown-error-format  Every error response SHOULD support either RFC 7807 (https://tools.ietf.org/html/rfc6648) or the JSON:API Error format.   paths./v1/orders.post.responses[401].content.application/json
  96:30  warning  no-unknown-error-format  Every error response SHOULD support either RFC 7807 (https://tools.ietf.org/html/rfc6648) or the JSON:API Error format.   paths./v1/orders/{order}.get.responses[401].content.application/json
 112:30  warning  no-unknown-error-format  Every error response SHOULD support either RFC 7807 (https://tools.ietf.org/html/rfc6648) or the JSON:API Error format.   paths./v1/orders/{order}.get.responses[404].content.application/json
```

Now you have some things to work on for your API. Thankfully these are only warnings, which are not going to [fail continuous integration](https://meta.stoplight.io/docs/spectral/ZG9jOjExNTMyOTAx-continuous-integration) (unless [you want them to](https://meta.stoplight.io/docs/spectral/ZG9jOjI1MTg1-spectral-cli#error-results)).


There are [a bunch of other rulesets](https://github.com/stoplightio/spectral-rulesets) you can check out if you feel like making your own API Style Guides, or feel like contributing some new rules here via a pull request.

## 🎉 Thanks

- [Andrzej](https://github.com/jerzyn) - Great rules contributed to the Adidas style guide.
- [Nauman Ali](https://github.com/naumanali-stoplight) - Creating the `no-global-versioning` rule as part of his excellent [style guide blog post series](https://blog.stoplight.io/consistent-api-urls-with-openapi-and-style-guides).

## 📜 License

This repository is licensed under the MIT license.

## 🌲 Sponsor

If you'd like to say thanks for this style guide, throw some money at [Protect Earth](https://protect.earth/donate), a charity that plants trees all over the United Kingdom, which has [secured a 64 acre ancient woodland to restore](https://www.protect.earth/blog/high-wood). Phil spends all his time on this, both planting trees _and_ writing APIs believe it or not!
