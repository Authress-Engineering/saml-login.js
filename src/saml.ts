import * as zlib from "zlib";
import { URL } from "url";
import * as querystring from "querystring";
import * as util from "util";
import {
  AudienceRestrictionXML,
  AuthorizeRequestXML,
  DelegationResponseXML,
  ErrorWithXmlStatus,
  Profile,
  XMLObject,
  XMLOutput,
  AuthenticationOptions,
  DelegationOptions,
  ValidationOptions,
  AuthenticationResponseMetadata
} from "./types";
import { assertRequired, signXmlResponse } from "./utility";
import {
  buildXml2JsObject,
  buildXmlBuilderObject,
  decryptXml,
  parseDomFromString,
  parseXml2JsFromString,
  validateXmlSignatureForCert,
  xpath,
} from "./xml";
import { certToPEM, generateUniqueId, keyToPEM } from "./crypto";
import { dateStringToTimestamp } from "./datetime";

const deflateRaw = util.promisify(zlib.deflateRaw);

// async function processValidlySignedSamlLogout(
//   doc: XMLOutput,
//   dom: Document
// ): Promise<{ profile?: Profile | null; loggedOut?: boolean }> {
//   const response = doc.LogoutResponse;
//   const request = doc.LogoutRequest;

//   if (response) {
//     return { profile: null, loggedOut: true };
//   } else if (request) {
//     return await processValidlySignedPostRequest( doc, dom);
//   } else {
//     throw new Error("Unknown SAML response message");
//   }
// }

class SamlLogin {
  private requestIdExpirationPeriodMs = 28800000;


  public async generateDelegationUrl(options: DelegationOptions) : Promise<string> {
    const id = generateUniqueId();
    const assertionId = generateUniqueId();
    const instantDateTime = options.requestTimestamp || new Date();

    const clockSkewDateTime = new Date(instantDateTime);
    clockSkewDateTime.setTime(clockSkewDateTime.getTime() - 5 * 60 * 1000);

    const expiryDateTime = new Date(instantDateTime);
    expiryDateTime.setTime(expiryDateTime.getTime() + 30 * 60 * 1000);

    const xmlResponse: DelegationResponseXML = {
      "samlp:Response": {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@ID": id,
        "@Version": "2.0",
        "@IssueInstant": instantDateTime.toISOString(),
        // "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "@Destination": options.applicationAssertionConsumerServiceUrl,
        "saml:Issuer": {
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "#text": options.issuerEntityId,
        },
        "samlp:Status": {
          "samlp:StatusCode": {
            "@Value": "urn:oasis:names:tc:SAML:2.0:status:Success",
          }
        },
        "saml:Assertion": {
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "@ID": assertionId,
          "@Version": "2.0",
          "@IssueInstant": instantDateTime.toISOString(),
          "saml:Issuer": {
            "#text": options.issuerEntityId,
          },
          "saml:Subject": {
            "saml:NameID": {
              "@Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
              "#text": options.userId
            },
            "saml:SubjectConfirmation": {
              "@Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer",
              "saml:SubjectConfirmationData": {
                "@NotOnOrAfter": expiryDateTime.toISOString(),
                "@Recipient": options.applicationAssertionConsumerServiceUrl
              }
            }
          },
          "saml:Conditions": {
            "@NotBefore": clockSkewDateTime.toISOString(),
            "@NotOnOrAfter": expiryDateTime.toISOString(),
            "saml:AudienceRestriction": {
              "saml:Audience": options.applicationEntityId
            }
          },
          "saml:AttributeStatement": {
            "saml:Attribute": {
              "@Name": "userId"
            }
          },
          "saml:AuthnStatement": {
            "@AuthnInstant": instantDateTime.toISOString(),
            "@SessionIndex": assertionId,
            "saml:AuthnContext": {
              "saml:AuthnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
            }
          }
        }
      },
    };

    if (options.state) {
      xmlResponse['samlp:Response']['@InResponseTo'] = options.state;
    }

    const unsignedResponse = buildXmlBuilderObject(xmlResponse, false);

    const signingOptions = {
      privateKey: keyToPEM(options.privateKey)
    };
    const signedResponse = signXmlResponse(unsignedResponse, signingOptions)

    const target = new URL(options.applicationAssertionConsumerServiceUrl);
    target.searchParams.set('SAMLResponse', Buffer.from(signedResponse).toString('base64'));
    target.searchParams.set('RelayState', options.state || '');

    // To test verify signature we just created:
    // const validationOptions = {
    //   providerCertificate: options.publicKey,
    //   expectedProviderIssuer: options.issuerEntityId,
    //   applicationEntityId: options.applicationEntityId
    // };
    // const { profile } = await this.validatePostResponse(validationOptions, target.searchParams.toString());
    return target.toString();
  }

  public async generateAuthenticationUrl(options: AuthenticationOptions) : Promise<string> {
    const providerSingleSignOnUrl = assertRequired(options.providerSingleSignOnUrl, "The provider's ACS URL `providerSingleSignOnUrl` is required");

    const id = options.authenticationRequestId || generateUniqueId();
    const instant = (options.requestTimestamp || new Date()).toISOString();

    const xmlRequest: AuthorizeRequestXML = {
      "samlp:AuthnRequest": {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@ID": id,
        "@Version": "2.0",
        "@IssueInstant": instant,
        "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "@Destination": providerSingleSignOnUrl,
        "saml:Issuer": {
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "#text": options.applicationEntityId,
        },
      },
    };

    xmlRequest["samlp:AuthnRequest"]["@AssertionConsumerServiceURL"] = options.applicationCallbackAssertionConsumerServiceUrl;

    xmlRequest["samlp:AuthnRequest"]["samlp:NameIDPolicy"] = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@Format": 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
      "@AllowCreate": options.allowCreate ? "true" : "false",
    };

    xmlRequest["samlp:AuthnRequest"]["samlp:RequestedAuthnContext"] = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@Comparison": 'exact',
      "saml:AuthnContextClassRef": [],
    };

    const request = buildXmlBuilderObject(xmlRequest, false);
    const buffer = await deflateRaw(request);
    const target = new URL(options.providerSingleSignOnUrl);
    target.searchParams.set('SAMLRequest', buffer.toString("base64"));
    return target.toString();
  }

  // This function checks that the |currentNode| in the |fullXml| document contains exactly 1 valid
  //   signature of the |currentNode|.
  validateSignature(fullXml: string, currentNode: Element, certs: string[]): boolean {
    const xpathSigQuery =
      ".//*[" +
      "local-name(.)='Signature' and " +
      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
      "descendant::*[local-name(.)='Reference' and @URI='#" +
      currentNode.getAttribute("ID") +
      "']" +
      "]";
    const signatures = xpath.selectElements(currentNode, xpathSigQuery);
    // This function is expecting to validate exactly one signature, so if we find more or fewer
    //   than that, reject.
    if (signatures.length !== 1) {
      return false;
    }
    const xpathTransformQuery =
      ".//*[" +
      "local-name(.)='Transform' and " +
      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
      "ancestor::*[local-name(.)='Reference' and @URI='#" +
      currentNode.getAttribute("ID") +
      "']" +
      "]";
    const transforms = xpath.selectElements(currentNode, xpathTransformQuery);
    // Reject also XMLDSIG with more than 2 Transform
    if (transforms.length > 2) {
      // do not return false, throw an error so that it can be caught by tests differently
      throw new Error("Invalid signature, too many transforms");
    }

    const signature = signatures[0];
    return certs && certs.filter(c => c).some((certToCheck) => {
      return validateXmlSignatureForCert(signature, certToPEM(certToCheck), fullXml, currentNode);
    });
  }

  public async getSamlAssertionMetadata(samlEncodedBody: string) : Promise<AuthenticationResponseMetadata> {
    const container = querystring.decode(samlEncodedBody);
    const xml = Buffer.from(container.SAMLResponse as string, "base64").toString("utf8");
    const doc = parseDomFromString(xml);

    if (!Object.prototype.hasOwnProperty.call(doc, "documentElement")) {
      throw new Error("SAMLResponse is not valid base64-encoded XML");
    }

    const inResponseToNodes = xpath.selectAttributes(doc, "/*[local-name()='Response']/@InResponseTo");
    const inResponseTo = inResponseToNodes && inResponseToNodes[0] && inResponseToNodes[0].nodeValue;
    if (inResponseTo) {
      return { authenticationRequestId: inResponseTo };
    }
    const error = Error('SAMLResponse does not have a valid authentication request ID.');
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore 2339
    error.code = 'InvalidAuthenticationRequestId';
    throw error;
  }

  public async validatePostResponse(options: ValidationOptions, samlEncodedBody: string): Promise<{ profile?: Profile | null; loggedOut?: boolean }> {
    const container = querystring.decode(samlEncodedBody);
    const xml = Buffer.from(container.SAMLResponse as string, "base64").toString("utf8");
    const doc = parseDomFromString(xml);

    if (!Object.prototype.hasOwnProperty.call(doc, "documentElement")) {
      throw new Error("SAMLResponse is not valid base64-encoded XML");
    }

    if (options.expectedProviderIssuer && doc.Response.Issuer && doc.Response.Issuer[0]._ !== options.expectedProviderIssuer) {
      throw new Error("Unknown SAML issuer. Expected: " + options.expectedProviderIssuer + " Received: " + doc.Response.Issuer[0]._);
    }

    const inResponseToNodes = xpath.selectAttributes(doc, "/*[local-name()='Response']/@InResponseTo");
    const inResponseTo = inResponseToNodes && inResponseToNodes[0] && inResponseToNodes[0].nodeValue;
    if (!inResponseTo) {
      throw new Error("InResponseTo is not valid");
    }
    
    if (options.requestTimestamp && new Date().getTime() > options.requestTimestamp.getTime() + this.requestIdExpirationPeriodMs) {
      throw new Error("ExpiredRequest");
    }
    const certs: string[] = !Array.isArray(options.providerCertificate) ? [options.providerCertificate] : options.providerCertificate;

    const assertions = xpath.selectElements(doc, "/*[local-name()='Response']/*[local-name()='Assertion']");
    const encryptedAssertions = xpath.selectElements(doc, "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']");

    if (assertions.length + encryptedAssertions.length > 1) {
      // There's no reason I know of that we want to handle multiple assertions, and it seems like a
      //   potential risk vector for signature scope issues, so treat this as an invalid signature
      throw new Error("Invalid signature: multiple assertions");
    }

    if (assertions.length) {
      try {
        if (!this.validateSignature(xml, doc.documentElement, certs) && !this.validateSignature(xml, assertions[0], certs)) {
          const error = new Error("Invalid signature");
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore 2339
          error.code = 'InvalidSignature';
          throw error;
        }
      } catch (error) {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore 2571
        if (error.code === 'ERR_OSSL_PEM_BAD_BASE64_DECODE') {
          const e = new Error("Invalid certificate");
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore 2339
          e.code = 'InvalidCertificate';
          throw e;
        }
        throw error;
      }
      return await this.processValidlySignedAssertion(assertions[0].toString(), xml, inResponseTo!, options.applicationEntityId);
    }

    if (encryptedAssertions.length) {
      const applicationPrivateKey = assertRequired(options.applicationPrivateKey, "No decryption key for encrypted SAML response");

      const encryptedAssertionXml = encryptedAssertions[0].toString();

      const decryptedXml = await decryptXml(encryptedAssertionXml, applicationPrivateKey);
      const decryptedDoc = parseDomFromString(decryptedXml);
      const decryptedAssertions = xpath.selectElements(decryptedDoc, "/*[local-name()='Assertion']");
      if (decryptedAssertions.length != 1) throw new Error("Invalid EncryptedAssertion content");

      if (!this.validateSignature(xml, doc.documentElement, certs) && !this.validateSignature(decryptedXml, decryptedAssertions[0], certs)) {
        throw new Error("Invalid signature from encrypted assertion");
      }

      return await this.processValidlySignedAssertion(decryptedAssertions[0].toString(), xml, inResponseTo!, options.applicationEntityId);
    }

    // If there's no assertion, fall back on xml2js response parsing for the status & LogoutResponse code.
    if (!this.validateSignature(xml, doc.documentElement, certs)) {
      throw new Error("Invalid signature: No response found");
    }

    const xmlJsDoc: XMLOutput = await parseXml2JsFromString(xml);
    if (xmlJsDoc.LogoutResponse) {
      return { profile: null, loggedOut: true };
    }

    const response = xmlJsDoc.Response;
    const assertion = response.Assertion;
    const status = response.Status;
    if (assertion || !status) {
      throw new Error("Missing valid SAML assertion");
    }

    const statusCode = status[0].StatusCode;
    if (statusCode && statusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:Responder") {
      const nestedStatusCode = statusCode[0].StatusCode;
      if (nestedStatusCode && nestedStatusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:NoPassive") {
        return { profile: null, loggedOut: false };
      }
    }

    // Note that we're not requiring a valid signature before this logic -- since we are
    //   throwing an error in any case, and some providers don't sign error results,
    //   let's go ahead and give the potentially more helpful error.
    if (statusCode && statusCode[0].$.Value) {
      const msgType = statusCode[0].$.Value.match(/[^:]*$/)[0];
      if (msgType != "Success") {
        let msg = "unspecified";
        if (status[0].StatusMessage) {
          msg = status[0].StatusMessage[0]._;
        } else if (statusCode[0].StatusCode) {
          msg = statusCode[0].StatusCode[0].$.Value.match(/[^:]*$/)[0];
        }
        const statusXml = buildXml2JsObject("Status", status[0]);
        throw new ErrorWithXmlStatus("SAML provider returned " + msgType + " error: " + msg, statusXml);
      }
    }

    throw new Error("Missing valid SAML assertion");
  }
  
  private async processValidlySignedAssertion(xml: string, samlResponseXml: string, inResponseTo: string, applicationEntityId: string) {
    const profile: XMLOutput = {};
    const doc = await parseXml2JsFromString(xml);
    const assertion = doc.Assertion;
    const subject = assertion.Subject;
    let subjectConfirmation, confirmData;
    if (subject) {
      const nameID = subject[0].NameID;
      if (nameID && nameID[0]._) {
        profile.nameID = nameID[0]._;

        if (nameID[0].$ && nameID[0].$.Format) {
          profile.nameIDFormat = nameID[0].$.Format;
          profile.nameQualifier = nameID[0].$.NameQualifier;
          profile.spNameQualifier = nameID[0].$.SPNameQualifier;
        }
      }

      subjectConfirmation = subject[0].SubjectConfirmation && subject[0].SubjectConfirmation[0];
      confirmData = subjectConfirmation && subjectConfirmation.SubjectConfirmationData && subjectConfirmation.SubjectConfirmationData[0];
      if (subjectConfirmation && subject[0].SubjectConfirmation.length > 1) {
        throw new Error("Unable to process multiple SubjectConfirmations in SAML assertion");
      }

      if (subjectConfirmation) {
        if (confirmData && confirmData.$) {
          const subjectNotBefore = confirmData.$.NotBefore;
          const subjectNotOnOrAfter = confirmData.$.NotOnOrAfter;
          const maxTimeLimitMs = this.processMaxAgeAssertionTime(this.requestIdExpirationPeriodMs, subjectNotOnOrAfter, assertion.$.IssueInstant);
          const subjErr = this.checkTimestampsValidityError(subjectNotBefore, subjectNotOnOrAfter, maxTimeLimitMs);
          if (subjErr) {
            throw subjErr;
          }
        }
      }
    }

    // Test to see that if we have a SubjectConfirmation InResponseTo that it matches
    // the 'InResponseTo' attribute set in the Response
    if (subjectConfirmation && confirmData && confirmData.$) {
      const subjectInResponseTo = confirmData.$.InResponseTo;
      if (subjectInResponseTo) {
        if (subjectInResponseTo != inResponseTo) {
          throw new Error("InResponseTo is not valid");
        }
      }
    }
    const conditions = assertion.Conditions ? assertion.Conditions[0] : null;
    if (assertion.Conditions && assertion.Conditions.length > 1) {
      throw new Error("Unable to process multiple conditions in SAML assertion");
    }
    if (conditions && conditions.$) {
      const maxTimeLimitMs = this.processMaxAgeAssertionTime(this.requestIdExpirationPeriodMs, conditions.$.NotOnOrAfter, assertion.$.IssueInstant);
      const conErr = this.checkTimestampsValidityError(conditions.$.NotBefore, conditions.$.NotOnOrAfter, maxTimeLimitMs);
      if (conErr) throw conErr;
    }

    const audienceErr = this.checkAudienceValidityError(applicationEntityId, conditions.AudienceRestriction);
    if (audienceErr) {
      throw audienceErr;
    }

    const attributeStatement = assertion.AttributeStatement;
    if (attributeStatement) {
      const attributes: XMLOutput[] = [].concat(
        ...attributeStatement
          .filter((attr: XMLObject) => Array.isArray(attr.Attribute))
          .map((attr: XMLObject) => attr.Attribute)
      );

      const attrValueMapper = (value: XMLObject) => {
        const hasChildren = Object.keys(value).some((cur) => {
          return cur !== "_" && cur !== "$";
        });
        return hasChildren ? value : value._;
      };

      if (attributes) {
        const profileAttributes: Record<string, unknown> = {};

        attributes.forEach((attribute) => {
          if (!Object.prototype.hasOwnProperty.call(attribute, "AttributeValue")) {
            // if attributes has no AttributeValue child, continue
            return;
          }

          const name = attribute.$.Name;
          const value =
            attribute.AttributeValue.length === 1
              ? attrValueMapper(attribute.AttributeValue[0])
              : attribute.AttributeValue.map(attrValueMapper);

          profileAttributes[name] = value;

          // If any property is already present in profile and is also present
          // in attributes, then skip the one from attributes. Handle this
          // conflict gracefully without returning any error
          if (Object.prototype.hasOwnProperty.call(profile, name)) {
            return;
          }

          profile[name] = value;
        });

        profile.attributes = profileAttributes;
      }
    }

    if (!profile.email && profile.mail) {
      profile.email = profile.mail;
    }
    if (!profile.email && profile["urn:oid:0.9.2342.19200300.100.1.3"]) {
      // See https://spaces.internet2.edu/display/InCFederation/Supported+Attribute+Summary for definition of attribute OIDs
      profile.email = profile["urn:oid:0.9.2342.19200300.100.1.3"];
    }

    return { profile, loggedOut: false };
  }

  private checkTimestampsValidityError(notBefore: string, notOnOrAfter: string, maxTimeLimitMs?: number, acceptedClockSkewMs = -1) {
    if (acceptedClockSkewMs == -1) return null;

    const nowMs = new Date().getTime();

    if (notBefore) {
      const notBeforeMs = dateStringToTimestamp(notBefore, "NotBefore");
      if (nowMs + acceptedClockSkewMs < notBeforeMs)
        return new Error("SAML assertion not yet valid");
    }
    if (notOnOrAfter) {
      const notOnOrAfterMs = dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
      if (nowMs - acceptedClockSkewMs >= notOnOrAfterMs)
        return new Error("SAML assertion expired: clocks skewed too much");
    }
    if (maxTimeLimitMs) {
      if (nowMs - acceptedClockSkewMs >= maxTimeLimitMs)
        return new Error("SAML assertion expired: assertion too old");
    }

    return null;
  }

  private checkAudienceValidityError(expectedAudience: string, audienceRestrictions: AudienceRestrictionXML[]) {
    if (new URL(expectedAudience).hostname === 'localhost' || new URL(expectedAudience).hostname === '127.0.0.1') {
      return null;
    }

    if (!audienceRestrictions || audienceRestrictions.length < 1) {
      return new Error("SAML assertion has no AudienceRestriction");
    }
    const errors = audienceRestrictions
      .map((restriction) => {
        if (!restriction.Audience || !restriction.Audience[0] || !restriction.Audience[0]._) {
          return new Error("SAML assertion AudienceRestriction has no Audience value");
        }
        if (restriction.Audience[0]._ !== expectedAudience) {
          return new Error("SAML assertion audience mismatch");
        }
        return null;
      })
      .filter((result) => {
        return result !== null;
      });
    if (errors.length > 0) {
      return errors[0];
    }
    return null;
  }

  /**
   * Process max age assertion and use it if it is more restrictive than the NotOnOrAfter age
   * assertion received in the SAMLResponse.
   *
   * @param maxAssertionAgeMs Max time after IssueInstant that we will accept assertion, in Ms.
   * @param notOnOrAfter Expiration provided in response.
   * @param issueInstant Time when response was issued.
   * @returns {*} The expiration time to be used, in Ms.
   */
  private processMaxAgeAssertionTime(maxAssertionAgeMs: number, notOnOrAfter: string, issueInstant: string): number {
    const notOnOrAfterMs = dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
    const issueInstantMs = dateStringToTimestamp(issueInstant, "IssueInstant");
    return Math.min(issueInstantMs + maxAssertionAgeMs, notOnOrAfterMs);
  }
}

export default SamlLogin;
