import * as zlib from "zlib";
import { URL } from "url";
import * as querystring from "querystring";
import * as util from "util";
import {
  AudienceRestrictionXML,
  AuthorizeRequestXML,
  ErrorWithXmlStatus,
  Profile,
  XMLObject,
  XMLOutput,
  AuthenticationOptions,
  ValidationOptions
} from "./types";
import { assertRequired } from "./utility";
import {
  buildXml2JsObject,
  buildXmlBuilderObject,
  decryptXml,
  parseDomFromString,
  parseXml2JsFromString,
  validateXmlSignatureForCert,
  xpath,
} from "./xml";
import { certToPEM, generateUniqueId } from "./crypto";
import { dateStringToTimestamp } from "./datetime";

const deflateRaw = util.promisify(zlib.deflateRaw);

interface NameID {
  value: string | null;
  format: string | null;
}

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

async function promiseWithNameID(nameId: Node): Promise<NameID> {
  const format = xpath.selectAttributes(nameId, "@Format");
  return {
    value: nameId.textContent,
    format: format && format[0] && format[0].nodeValue,
  };
}

class SamlLogin {
  private requestIdExpirationPeriodMs = 28800000;
  // private signRequest(samlMessage: querystring.ParsedUrlQueryInput): void {
  //   options.privateKey = assertRequired(options.privateKey, "privateKey is required");

  //   const samlMessageToSign: querystring.ParsedUrlQueryInput = {};
  //   samlMessage.SigAlg = algorithms.getSigningAlgorithm(options.signatureAlgorithm);
  //   const signer = algorithms.getSigner(options.signatureAlgorithm);
  //   if (samlMessage.SAMLRequest) {
  //     samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest;
  //   }
  //   if (samlMessage.SAMLResponse) {
  //     samlMessageToSign.SAMLResponse = samlMessage.SAMLResponse;
  //   }
  //   if (samlMessage.RelayState) {
  //     samlMessageToSign.RelayState = samlMessage.RelayState;
  //   }
  //   if (samlMessage.SigAlg) {
  //     samlMessageToSign.SigAlg = samlMessage.SigAlg;
  //   }
  //   signer.update(querystring.stringify(samlMessageToSign));
  //   samlMessage.Signature = signer.sign(keyToPEM(options.privateKey), "base64");
  // }

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

    // if (options.forceAuthn) {
    //   xmlRequest["samlp:AuthnRequest"]["@ForceAuthn"] = true;
    // }

    xmlRequest["samlp:AuthnRequest"]["@AssertionConsumerServiceURL"] = options.applicationCallbackAssertionConsumerServiceUrl;

    xmlRequest["samlp:AuthnRequest"]["samlp:NameIDPolicy"] = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@Format": 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
      "@AllowCreate": "true",
    };

    // const authnContextClassRefs: XMLInput[] = [];
    // (options.authnContext as string[]).forEach(function (value) {
    //   authnContextClassRefs.push({
    //     "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    //     "#text": value,
    //   });
    // });

    xmlRequest["samlp:AuthnRequest"]["samlp:RequestedAuthnContext"] = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@Comparison": 'exact',
      "saml:AuthnContextClassRef": [],
    };

    // if (options.attributeConsumingServiceIndex != null) {
    //   xmlRequest["samlp:AuthnRequest"]["@AttributeConsumingServiceIndex"] =
    //     options.attributeConsumingServiceIndex;
    // }

    // if (options.applicationName != null) {
    //   xmlRequest["samlp:AuthnRequest"]["@ProviderName"] = options.applicationName;
    // }

    // if (options.scoping != null) {
    //   const scoping: XMLInput = {
    //     "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    //   };

    //   if (typeof options.scoping.proxyCount === "number") {
    //     scoping["@ProxyCount"] = options.scoping.proxyCount;
    //   }

    //   if (options.scoping.idpList) {
    //     scoping["samlp:IDPList"] = options.scoping.idpList.map(
    //       (idpListItem: SamlIDPListConfig) => {
    //         const formattedIdpListItem: XMLInput = {
    //           "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    //         };

    //         if (idpListItem.entries) {
    //           formattedIdpListItem["samlp:IDPEntry"] = idpListItem.entries.map(
    //             (entry: SamlIDPEntryConfig) => {
    //               const formattedEntry: XMLInput = {
    //                 "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    //               };

    //               formattedEntry["@ProviderID"] = entry.providerId;

    //               if (entry.name) {
    //                 formattedEntry["@Name"] = entry.name;
    //               }

    //               if (entry.loc) {
    //                 formattedEntry["@Loc"] = entry.loc;
    //               }

    //               return formattedEntry;
    //             }
    //           );
    //         }

    //         if (idpListItem.getComplete) {
    //           formattedIdpListItem["samlp:GetComplete"] = idpListItem.getComplete;
    //         }

    //         return formattedIdpListItem;
    //       }
    //     );
    //   }

    //   if (options.scoping.requesterId) {
    //     scoping["samlp:RequesterID"] = options.scoping.requesterId;
    //   }

    //   xmlRequest["samlp:AuthnRequest"]["samlp:Scoping"] = scoping;
    // }

    const request = buildXmlBuilderObject(xmlRequest, false);
    const buffer = await deflateRaw(request);
    const target = new URL(options.providerSingleSignOnUrl);
    target.searchParams.set('SAMLRequest', buffer.toString("base64"));
    return target.toString();
  }

  // public async generateLogoutRequest(user: Profile, options: LogoutOptions) : Promise<string> {
  //   const id = options.generateUniqueId();
  //   const instant = generateInstant();

  //   const request = {
  //     "samlp:LogoutRequest": {
  //       "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
  //       "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
  //       "@ID": id,
  //       "@Version": "2.0",
  //       "@IssueInstant": instant,
  //       "@Destination": options.logoutUrl,
  //       "saml:Issuer": {
  //         "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
  //         "#text": options.issuer,
  //       },
  //       "saml:NameID": {
  //         "@Format": user!.nameIDFormat,
  //         "#text": user!.nameID,
  //       },
  //     },
  //   } as LogoutRequestXML;

  //   if (user!.nameQualifier != null) {
  //     request["samlp:LogoutRequest"]["saml:NameID"]["@NameQualifier"] = user!.nameQualifier;
  //   }

  //   if (user!.spNameQualifier != null) {
  //     request["samlp:LogoutRequest"]["saml:NameID"]["@SPNameQualifier"] = user!.spNameQualifier;
  //   }

  //   if (user!.sessionIndex) {
  //     request["samlp:LogoutRequest"]["saml2p:SessionIndex"] = {
  //       "@xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
  //       "#text": user!.sessionIndex,
  //     };
  //   }

  //   await this.cacheProvider.save(id, instant);
  //   const request = buildXmlBuilderObject(request, false);
  //   await this._requestToUrl(request, null, "logout");
  // }

  // public async generateLogoutResponse(user: Profile, options: LogoutOptions) : Promise<string> {
  //   const id = options.generateUniqueId();
  //   const instant = generateInstant();

  //   const request = {
  //     "samlp:LogoutResponse": {
  //       "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
  //       "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
  //       "@ID": id,
  //       "@Version": "2.0",
  //       "@IssueInstant": instant,
  //       "@Destination": options.logoutUrl,
  //       "@InResponseTo": logoutRequest.ID,
  //       "saml:Issuer": {
  //         "#text": options.issuer,
  //       },
  //       "samlp:Status": {
  //         "samlp:StatusCode": {
  //           "@Value": "urn:oasis:names:tc:SAML:2.0:status:Success",
  //         },
  //       },
  //     },
  //   };

  //   return buildXmlBuilderObject(request, false);
  // }

  // private async _requestToUrl(
  //   request: string | null | undefined,
  //   response: string | null,
  //   operation: string,
  //   additionalParameters: querystring.ParsedUrlQuery
  // ): Promise<string> {
  //   providerSingleSignOnUrl = assertRequired(options.providerSingleSignOnUrl, "providerSingleSignOnUrl is required");

  //   let buffer: Buffer;
  //   if (options.skipRequestCompression) {
  //     buffer = Buffer.from((request || response)!, "utf8");
  //   } else {
  //     buffer = await deflateRaw((request || response)!);
  //   }

  //   const base64 = buffer.toString("base64");
  //   let target = new URL(providerSingleSignOnUrl);

  //   if (operation === "logout") {
  //     if (options.logoutUrl) {
  //       target = new URL(options.logoutUrl);
  //     }
  //   } else if (operation !== "authorize") {
  //     throw new Error("Unknown operation: " + operation);
  //   }

  //   const samlMessage: querystring.ParsedUrlQuery = request
  //     ? {
  //         SAMLRequest: base64,
  //       }
  //     : {
  //         SAMLResponse: base64,
  //       };
  //   Object.keys(additionalParameters).forEach((k) => {
  //     samlMessage[k] = additionalParameters[k];
  //   });
  //   if (options.privateKey != null) {
  //     if (!providerSingleSignOnUrl) {
  //       throw new Error('"providerSingleSignOnUrl" config parameter is required for signed messages');
  //     }

  //     // sets .SigAlg and .Signature
  //     this.signRequest(samlMessage);
  //   }
  //   Object.keys(samlMessage).forEach((k) => {
  //     target.searchParams.set(k, samlMessage[k] as string);
  //   });

  //   return target.toString();
  // }

  // public async getLogoutResponseUrl(options: LogoutResponseOptions) : Promise<string> {
  //   const response = this._generateLogoutResponse(samlLogoutRequest);
  //   return await this._requestToUrl(null, response, 'logout');
  // }

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

  async getAuthenticationRequestIdFromSamlAssertion(samlEncodedBody: string) : Promise<string> {
    const container = querystring.decode(samlEncodedBody);
    const xml = Buffer.from(container.SAMLResponse as string, "base64").toString("utf8");
    const doc = parseDomFromString(xml);

    if (!Object.prototype.hasOwnProperty.call(doc, "documentElement")) {
      throw new Error("SAMLResponse is not valid base64-encoded XML");
    }

    const inResponseToNodes = xpath.selectAttributes(doc, "/*[local-name()='Response']/@InResponseTo");
    const inResponseTo = inResponseToNodes && inResponseToNodes[0] && inResponseToNodes[0].nodeValue;
    if (inResponseTo) {
      return inResponseTo;
    }
    throw Error('SAMLResponse does not have a valid authentication request ID.');
  }

  async validatePostResponse(options: ValidationOptions, samlEncodedBody: string): Promise<{ profile?: Profile | null; authenticationRequest?: Record<string, unknown>; loggedOut?: boolean }> {
    const container = querystring.decode(samlEncodedBody);
    const xml = Buffer.from(container.SAMLResponse as string, "base64").toString("utf8");
    const doc = parseDomFromString(xml);

    if (!Object.prototype.hasOwnProperty.call(doc, "documentElement")) {
      throw new Error("SAMLResponse is not valid base64-encoded XML");
    }

    // TODO: Fix issuer validation on response
    // if (options.expectedProviderIssuer && !doc.Response.Issuer) {
    //   throw new Error("Missing SAML issuer");
    // }

    // if (options.expectedProviderIssuer && doc.Response.Issuer[0]._ !== options.expectedProviderIssuer) {
    //   throw new Error("Unknown SAML issuer. Expected: " + options.expectedProviderIssuer + " Received: " + doc.Response.Issuer[0]._);
    // }

    const inResponseToNodes = xpath.selectAttributes(doc, "/*[local-name()='Response']/@InResponseTo");
    const inResponseTo = inResponseToNodes && inResponseToNodes[0] && inResponseToNodes[0].nodeValue;
    if (!inResponseTo) {
      throw new Error("InResponseTo is not valid");
    }
    
    if (options.requestTimestamp && new Date().getTime() > new Date(options.requestTimestamp).getTime() + this.requestIdExpirationPeriodMs) {
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
      if (!this.validateSignature(xml, doc.documentElement, certs) && !this.validateSignature(xml, assertions[0], certs)) {
        throw new Error("Invalid signature");
      }
      return await this.processValidlySignedAssertion(assertions[0].toString(), xml, inResponseTo!, options.applicationEntityId);
    }

    if (encryptedAssertions.length) {
      assertRequired(options.applicationPrivateKey, "No decryption key for encrypted SAML response");

      const encryptedAssertionXml = encryptedAssertions[0].toString();

      const decryptedXml = await decryptXml(encryptedAssertionXml, options.applicationPrivateKey);
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

    const xmlJsDoc = await parseXml2JsFromString(xml);
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
    let msg;
    const profile = {} as Profile;
    const doc: XMLOutput = await parseXml2JsFromString(xml);
    const assertion: XMLOutput = doc.Assertion;

    const issuer: unknown = assertion.Issuer;
    if (issuer && issuer[0]._) {
      profile.issuer = issuer[0]._;
    }

    if (inResponseTo) {
      profile.inResponseTo = inResponseTo;
    }

    const authnStatement = assertion.AuthnStatement;
    if (authnStatement) {
      if (authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
        profile.sessionIndex = authnStatement[0].$.SessionIndex;
      }
    }

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
        msg = "Unable to process multiple SubjectConfirmations in SAML assertion";
        throw new Error(msg);
      }

      if (subjectConfirmation) {
        if (confirmData && confirmData.$) {
          const subjectNotBefore = confirmData.$.NotBefore;
          const subjectNotOnOrAfter = confirmData.$.NotOnOrAfter;
          const maxTimeLimitMs = this.processMaxAgeAssertionTime(this.requestIdExpirationPeriodMs, subjectNotOnOrAfter, assertion.$.IssueInstant);

          const nowMs = new Date().getTime();
          const subjErr = this.checkTimestampsValidityError(nowMs, subjectNotBefore, subjectNotOnOrAfter, maxTimeLimitMs);
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
      msg = "Unable to process multiple conditions in SAML assertion";
      throw new Error(msg);
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

    if (!profile.mail && profile["urn:oid:0.9.2342.19200300.100.1.3"]) {
      // See https://spaces.internet2.edu/display/InCFederation/Supported+Attribute+Summary
      // for definition of attribute OIDs
      profile.mail = profile["urn:oid:0.9.2342.19200300.100.1.3"];
    }

    if (!profile.email && profile.mail) {
      profile.email = profile.mail;
    }

    return { profile, authenticationRequest, loggedOut: false };
  }

  private checkTimestampsValidityError(notBefore: string, notOnOrAfter: string, maxTimeLimitMs?: number) {
    if (options.acceptedClockSkewMs == -1) return null;

    const nowMs = new Date().getTime();

    if (notBefore) {
      const notBeforeMs = dateStringToTimestamp(notBefore, "NotBefore");
      if (nowMs + options.acceptedClockSkewMs < notBeforeMs)
        return new Error("SAML assertion not yet valid");
    }
    if (notOnOrAfter) {
      const notOnOrAfterMs = dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
      if (nowMs - options.acceptedClockSkewMs >= notOnOrAfterMs)
        return new Error("SAML assertion expired: clocks skewed too much");
    }
    if (maxTimeLimitMs) {
      if (nowMs - options.acceptedClockSkewMs >= maxTimeLimitMs)
        return new Error("SAML assertion expired: assertion too old");
    }

    return null;
  }

  private checkAudienceValidityError(
    expectedAudience: string,
    audienceRestrictions: AudienceRestrictionXML[]
  ) {
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

  // private async _getNameId(doc: Node, applicationPrivateKey: string): Promise<NameID> {
  //   const nameIds = xpath.selectElements(doc, "/*[local-name()='LogoutRequest']/*[local-name()='NameID']");
  //   const encryptedIds = xpath.selectElements(doc, "/*[local-name()='LogoutRequest']/*[local-name()='EncryptedID']");

  //   if (nameIds.length + encryptedIds.length > 1) {
  //     throw new Error("Invalid LogoutRequest");
  //   }
  //   if (nameIds.length === 1) {
  //     return promiseWithNameID(nameIds[0]);
  //   }
  //   if (encryptedIds.length === 1) {
  //     assertRequired(applicationPrivateKey, "No decryption key found getting name ID for encrypted SAML response");

  //     const encryptedDataList = xpath.selectElements(encryptedIds[0], "./*[local-name()='EncryptedData']");

  //     if (encryptedDataList.length !== 1) {
  //       throw new Error("Invalid LogoutRequest");
  //     }
  //     const encryptedDataXml = encryptedDataList[0].toString();

  //     const decryptedXml = await decryptXml(encryptedDataXml, applicationPrivateKey);
  //     const decryptedDoc = parseDomFromString(decryptedXml);
  //     const decryptedIds = xpath.selectElements(decryptedDoc, "/*[local-name()='NameID']");
  //     if (decryptedIds.length !== 1) {
  //       throw new Error("Invalid EncryptedAssertion content");
  //     }
  //     return await promiseWithNameID(decryptedIds[0]);
  //   }
  //   throw new Error("Missing SAML NameID");
  // }

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
