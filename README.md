# Node SAML
[![NPM](https://nodei.co/npm/saml-login.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/saml-login/)
[![npm version](https://badge.fury.io/js/saml-login.svg)](http://badge.fury.io/js/saml-login)

This is a [SAML 2.0](http://en.wikipedia.org/wiki/SAML_2.0) authentication provider for applications, service providers, and IdP for Node.js

## Installation
```sh
npm install saml-login
```

## Usage

### Configure strategy

The SAML identity provider will redirect you to the URL provided by the `path` configuration.

```javascript
const samlLogin = require("saml-login");

const options = {

};
const idpAuthenticationUrl = await samlLogin.generateAuthenticationUrl(options);
```

#### Config options details:

- **Core**
- `callbackUrl`: full callbackUrl (overrides path/protocol if supplied)
- `entryPoint`: identity provider entrypoint (is required to be spec-compliant when the request is signed)
- `issuer`: issuer string to supply to identity provider
- `audience`: expected saml response Audience (if not provided, Audience won't be verified)
- `cert`: the IDP's public signing certificate used to validate the signatures of the incoming SAML Responses, see [Security and signatures](#security-and-signatures)
- `signatureAlgorithm`: optionally set the signature algorithm for signing requests, valid values are 'sha1' (default), 'sha256', or 'sha512'
- `digestAlgorithm`: optionally set the digest algorithm used to provide a digest for the signed data object, valid values are 'sha1' (default), 'sha256', or 'sha512'
- **Additional SAML behaviors**
- `additionalParams`: dictionary of additional query params to add to all requests; if an object with this key is passed to `authenticate`, the dictionary of additional query params will be appended to those present on the returned URL, overriding any specified by initialization options' additional parameters (`additionalParams`, `additionalAuthorizeParams`, and `additionalLogoutParams`)
- `additionalAuthorizeParams`: dictionary of additional query params to add to 'authorize' requests
- `identifierFormat`: optional name identifier format to request from identity provider (default: `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`)
- `forceAuthn`: if set to true, the initial SAML request from the service provider specifies that the IdP should force re-authentication of the user, even if they possess a valid session.
- `providerName`: optional human-readable name of the requester for use by the presenter's user agent or the identity provider

- **Issuer Validation**
- `idpIssuer`: if provided, then the IdP issuer will be validated for incoming Logout Requests/Responses. For ADFS this looks like `https://acme_tools.windows.net/deadbeef`
- **Logout**
- `additionalLogoutParams`: dictionary of additional query params to add to 'logout' requests
- `logoutCallbackUrl`: The value with which to populate the `Location` attribute in the `SingleLogoutService` elements in the generated service provider metadata.

For more detailed instructions, see [ADFS documentation](docs/adfs/README.md).

## SAML Response Validation - NotBefore and NotOnOrAfter

If the `NotBefore` or the `NotOnOrAfter` attributes are returned in the SAML response, SAML-Login will validate them
against the current time +/- a configurable clock skew value. The default for the skew is 0s. This is to account for
differences between the clock time on the client (SAML-Login service provider) and the server (Identity provider).

`NotBefore` and `NotOnOrAfter` can be part of either the `SubjectConfirmation` element, or within in the `Assertion/Conditions` element
in the SAML response.

## SLO (single logout)

- Signature validation
- IdP initiated and SP initiated logouts


## ChangeLog

See [Changelog](https://github.com/authress/saml-login.js/blob/master/CHANGELOG.md)