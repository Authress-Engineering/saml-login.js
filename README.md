<p id="main" align="center">
  <img src="https://authress.io/static/images/linkedin-banner.png" alt="Authress media banner">
</p>

# Full SAML2.0 integration for NodeJS
[![npm version](https://badge.fury.io/js/saml-login.svg)](https://badge.fury.io/js/saml-login)

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

## ChangeLog

See [Changelog](https://github.com/authress/saml-login.js/blob/master/CHANGELOG.md)
