# Node SAML
[![npm version](https://badge.fury.io/js/saml-login.svg)](http://badge.fury.io/js/saml-login)

This is a [SAML 2.0](http://en.wikipedia.org/wiki/SAML_2.0) authentication provider for applications, service providers, and IdP for Node.js

## Installation
```sh
npm install saml-login
```

## Usage

### Generate Authentication URL

The SAML identity provider will redirect you to the URL provided by the `path` configuration.

```javascript
const { SAML } = require("saml-login");
const saml = new SAML();

const options = {
  /** The provider's SSO URL. Where to direct the user to login and verify their identity. */
  providerSingleSignOnUrl: 'string',
  /** A unique ID generated for the request which can be used to verify later that the response is valid. If not specified an ID will be generated automatically. */
  authenticationRequestId: 'string',
  /** The date of the request, later this date will be used to verify the response, if it is not provided here, it will automatically generated. */
  requestTimestamp: new Date(),
  /** Your application's entity Id, should be a fully qualified URL, and must match the application entityId specified to the IdP.  */
  applicationEntityId: 'string',
  /** Your application's ACS SSO callback URL and must match the one registered with the IdP. This URL will receive the response from the IdP and must return a 302. */
  applicationCallbackAssertionConsumerServiceUrl: 'string',
};

const idpAuthenticationUrl = await saml.generateAuthenticationUrl(options);
```

### Verify and Parse Login Response
```javascript
const { SAML } = require("saml-login");
const saml = new SAML();

const options = {
  /** Identity provider public certificate to use for verifying the signature of the SAML Response. */
  providerCertificate: 'string',

  /** Your application's entity Id, should be a fully qualified URL, and must match the application entityId specified to the IdP, used to verify the response.  */
  applicationEntityId: 'string'
};

const { authenticationRequestId } = await saml.getSamlAssertionMetadata(request.body);
const { profile } = await saml.validatePostResponse(options, request.body);
```

### Generate SAML Delegation URL
When the user is already logged into your application, and you want to log the user into a third party using their existing authentication. This generates the SAML Payload and URL to redirect the user to

```js
const { SAML } = require("saml-login");
const saml = new SAML();

const options = {
  /** Your platforms IdP Entity ID or URL */
  issuerEntityId: 'https://my.idp.com',
  /** Your private key to sign the delegation request. */
  privateKey: '----BEGIN PRIVATE KEY...',
  /** Your application's entity Id, should be a fully qualified URL, and must match the application entityId specified to the IdP.  */
  applicationEntityId: 'https://thirdpart.application.com/',
  /** Your application's ACS SSO callback URL and must match the one registered with the IdP. This URL will receive the response from the IdP and must return a 302. */
  applicationAssertionConsumerServiceUrl: 'https://thirdpart.application.com/saml',
  /** The relevant user that wants to log into the third party application. */
  userId: 'user_id'
};

const spDelegationUrl = await saml.generateDelegationUrl(options);
```

#### Config options details:

- **Core**
- `callbackUrl`: full callbackUrl (overrides path/protocol if supplied)
- `providerSingleSignOnUrl`: identity provider providerSingleSignOnUrl (is required to be spec-compliant when the request is signed)
- `issuer`: issuer string to supply to identity provider
- `audience`: expected saml response Audience (if not provided, Audience won't be verified)
- `cert`: the IDP's public signing certificate used to validate the signatures of the incoming SAML Responses, see [Security and signatures](#security-and-signatures)
- `signatureAlgorithm`: optionally set the signature algorithm for signing requests, valid values are 'sha1' (default), 'sha256', or 'sha512'
- `digestAlgorithm`: optionally set the digest algorithm used to provide a digest for the signed data object, valid values are 'sha1' (default), 'sha256', or 'sha512'
- **Additional SAML behaviors**
- `additionalParams`: dictionary of additional query params to add to all requests; if an object with this key is passed to `authenticate`, the dictionary of additional query params will be appended to those present on the returned URL, overriding any specified by initialization options' additional parameters (`additionalParams`, `additionalAuthorizeParams`, and `additionalLogoutParams`)
- `additionalAuthorizeParams`: dictionary of additional query params to add to 'authorize' requests
- `forceAuthn`: if set to true, the initial SAML request from the service provider specifies that the IdP should force re-authentication of the user, even if they possess a valid session.

- **Issuer Validation**
- `expectedProviderIssuer`: if provided, then the IdP issuer will be validated for incoming Logout Requests/Responses. For ADFS this looks like `https://acme_tools.windows.net/adfs-example`
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
