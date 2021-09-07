# Node SAML

[![Build Status](https://github.com/authress/saml-login.js/workflows/Build%20Status/badge.svg)](https://github.com/authress/saml-login.js/actions?query=workflow%3ABuild%Status) [![GitHub version](https://badge.fury.io/gh/saml-login%2Fsaml-login.svg)](https://badge.fury.io/gh/saml-login%2Fsaml-login) [![npm version](https://badge.fury.io/js/saml-login.svg)](http://badge.fury.io/js/saml-login) [![NPM](https://nodei.co/npm/saml-login.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/saml-login/) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

This is a [SAML 2.0](http://en.wikipedia.org/wiki/SAML_2.0) authentication provider for Node.js.


## Installation
```sh
npm install saml-login
```

## Usage

### Configure strategy

The SAML identity provider will redirect you to the URL provided by the `path` configuration.

```javascript
const SamlLogin = require("saml-login");

const options = {};
const saml = new SamlLogin(options);
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

If the `NotBefore` or the `NotOnOrAfter` attributes are returned in the SAML response, Passport-SAML will validate them
against the current time +/- a configurable clock skew value. The default for the skew is 0s. This is to account for
differences between the clock time on the client (Node server with Passport-SAML) and the server (Identity provider).

`NotBefore` and `NotOnOrAfter` can be part of either the `SubjectConfirmation` element, or within in the `Assertion/Conditions` element
in the SAML response.

## Subject confirmation validation

When configured (turn `validateInResponseTo` to `true` in the Passport-SAML config), the `InResponseTo` attribute will be validated.
Validation will succeed if Passport-SAML previously generated a SAML request with an id that matches the value of `InResponseTo`.

Also note that `InResponseTo` is validated as an attribute of the top level `Response` element in the SAML response, as well
as part of the `SubjectConfirmation` element.

Previous request id's generated for SAML requests will eventually expire. This is controlled with the `requestIdExpirationPeriodMs` option
passed into the Passport-SAML config. The default is 28,800,000 ms (8 hours). Once expired, a subsequent SAML response
received with an `InResponseTo` equal to the expired id will not validate and an error will be returned.

## Cache Provider

When `InResponseTo` validation is turned on, Passport-SAML will store generated request ids used in SAML requests to the IdP. The implementation
of how things are stored, checked to see if they exist, and eventually removed is from the Cache Provider used by Passport-SAML.

The default implementation is a simple in-memory cache provider. For multiple server/process scenarios, this will not be sufficient as
the server/process that generated the request id and stored in memory could be different than the server/process handling the
SAML response. The `InResponseTo` could fail in this case erroneously.

To support this scenario you can provide an implementation for a cache provider by providing an object with following functions:

```javascript
{
    save: function(key, value, callback) {
      // save the key with the optional value, invokes the callback with the value saves
    },
    get: function(key, callback) {
      // invokes 'callback' and passes the value if found, null otherwise
    },
    remove: function(key, callback) {
      // removes the key from the cache, invokes `callback` with the
      // key removed, null if no key is removed
    }
}
```

The `callback` argument is a function in the style of normal Node callbacks:

```
function callback(err, result)
{

}
```

Provide an instance of an object which has these functions passed to the `cacheProvider` config option when using Passport-SAML.

## SLO (single logout)

Passport-SAML has built in support for SLO including

- Signature validation
- IdP initiated and SP initiated logouts
- Decryption of encrypted name identifiers in IdP initiated logout
- `Redirect` and `POST` SAML Protocol Bindings

## ChangeLog

See [Changelog](https://github.com/authress/saml-login.js/blob/master/CHANGELOG.md)