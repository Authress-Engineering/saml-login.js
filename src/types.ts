export type SignatureAlgorithm = "sha1" | "sha256" | "sha512";

export interface SamlSigningOptions {
  privateKey: string | Buffer;
  signatureAlgorithm?: SignatureAlgorithm;
  xmlSignatureTransforms?: string[];
  digestAlgorithm?: string;
}

export const isValidSamlSigningOptions = (
  options: Partial<SamlSigningOptions>
): options is SamlSigningOptions => {
  return options.privateKey != null;
};

export interface AudienceRestrictionXML {
  Audience?: XMLObject[];
}

export type XMLValue = string | number | boolean | null | XMLObject | XMLValue[];

export type XMLObject = {
  [key: string]: XMLValue;
};

export type XMLInput = XMLObject;

export type XMLOutput = Record<string, unknown>;

export interface AuthorizeRequestXML extends Record<string, unknown> {
  "samlp:AuthnRequest": XMLInput;
}

export type CertCallback = (
  callback: (err: Error | null, cert?: string | string[]) => void
) => void;

/**
 * These are SAML options that must be provided to construct a new SAML Strategy
 */
export interface MandatorySamlOptions {
  cert: string | string[] | CertCallback;
}

export interface SamlIDPListConfig {
  entries: SamlIDPEntryConfig[];
  getComplete?: string;
}

export interface SamlIDPEntryConfig {
  providerId: string;
  name?: string;
  loc?: string;
}

export interface LogoutRequestXML {
  "samlp:LogoutRequest": {
    "saml:NameID": XMLInput;
    [key: string]: XMLValue;
  };
}

export interface ServiceMetadataXML {
  EntityDescriptor: {
    [key: string]: XMLValue;
    SPSSODescriptor: XMLObject;
  };
}

export interface AuthenticationOptions {
  /** The provider's SSO URL. Where to direct the user to login and verify their identity. */
  providerSingleSignOnUrl: string;
  /** A unique ID generated for the request which can be used to verify later that the response is valid. If not specified an ID will be generated automatically. */
  authenticationRequestId?: string;
  /** The date of the request, later this date will be used to verify the response, if it is not provided here, it will automatically generated. */
  requestTimestamp?: Date;
  /** Your application's entity Id, should be a fully qualified URL, and must match the application entityId specified to the IdP.  */
  applicationEntityId: string;
  /** Your application's ACS SSO callback URL and must match the one registered with the IdP. This URL will receive the response from the IdP and must return a 302. */
  applicationCallbackAssertionConsumerServiceUrl: string;
}

export interface ValidationOptions {
  /** The date of the request created, if it is not provided here, it will not be validated. */
  requestTimestamp?: Date;

  /** Identity provider public certificate to use for verifying the signature of the SAML Response. */
  providerCertificate: string | string[];

  /** Expected IdP Issuer found in SAML. */
  expectedProviderIssuer?: string;

  /** Your application's entity Id, should be a fully qualified URL, and must match the application entityId specified to the IdP, used to verify the response.  */
  applicationEntityId: string;

  /** Your application's private key used to decrypt assertions if they were requested to be signed on authentication. */
  applicationPrivateKey?: string;
}

export interface Profile {
  issuer?: string;
  sessionIndex?: string;
  nameID?: string;
  nameIDFormat?: string;
  nameQualifier?: string;
  spNameQualifier?: string;
  ID?: string;
  mail?: string; // InCommon Attribute urn:oid:0.9.2342.19200300.100.1.3
  email?: string; // `mail` if not present in the assertion
  ["urn:oid:0.9.2342.19200300.100.1.3"]?: string;
  [attributeName: string]: unknown; // arbitrary `AttributeValue`s
}

export class ErrorWithXmlStatus extends Error {
  constructor(message: string, public readonly xmlStatus: string) {
    super(message);
  }
}
