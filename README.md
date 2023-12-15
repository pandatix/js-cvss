<div align="center">
	<h1>JS-CVSS</h1>
    <a href="https://www.npmjs.com/package/@pandatix/js-cvss"><img src="https://img.shields.io/npm/dm/%40pandatix%2Fjs-cvss?style=for-the-badge" alt="NPM"></a>
	<br>
	<a href=""><img src="https://img.shields.io/github/license/pandatix/js-cvss?style=for-the-badge" alt="License"></a>
	<a href="https://github.com/pandatix/js-cvss/actions?query=workflow%3Aci+"><img src="https://img.shields.io/github/actions/workflow/status/pandatix/js-cvss/ci.yaml?style=for-the-badge&label=CI" alt="CI"></a>
	<a href="https://github.com/pandatix/js-cvss/actions/workflows/codeql-analysis.yaml"><img src="https://img.shields.io/github/actions/workflow/status/pandatix/js-cvss/codeql-analysis.yaml?style=for-the-badge&label=CodeQL" alt="CodeQL"></a>
	<br>
	<a href="https://securityscorecards.dev/viewer/?uri=github.com/pandatix/js-cvss"><img src="https://img.shields.io/ossf-scorecard/github.com/pandatix/js-cvss?label=openssf%20scorecard&style=for-the-badge" alt="OpenSSF Scoreboard"></a>
</div>

js-cvss is another Common Vulnerability Scoring System (CVSS) implementation, in TypeScript.

> **Note**
>
> Specified by [first.org](https://www.first.org/cvss/), the CVSS provides a way to capture the principal characteristics of a vulnerability and produce a numerical score reflecting its severity.

It currently supports :
 - [X] [CVSS 2.0](https://www.first.org/cvss/v2/guide)
 - [X] [CVSS 3.0](https://www.first.org/cvss/v3.0/specification-document)
 - [X] [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)
 - [X] [CVSS 4.0](https://www.first.org/cvss/v4.0/specification-document)

> **Warning**
>
> It won't support CVSS v1.0, as despite it was a good CVSS start, it can't get vectorized, abbreviations and enumerations are not strongly specified, so the cohesion and interoperability can't be satisfied.

## How to use

From your project, you can add `@pandatix/js-cvss` to your NPM dependencies using the following.
```bash
npm install '@pandatix/js-cvss' -D
```

Then, from your code, import what you need (let's say `CVSS40``) and go on !

```ts
import { CVSS40 } from '@pandatix/js-cvss';

...

let vec = CVSS40('CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L');
console.log(vec.Score());
```
