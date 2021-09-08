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

export type XMLOutput = Record<string, any>;

export interface AuthorizeRequestXML {
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

export type RacComparision = "exact" | "minimum" | "maximum" | "better";

interface SamlScopingConfig {
  idpList?: SamlIDPListConfig[];
  proxyCount?: number;
  requesterId?: string[] | string;
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

/**
 * The options required to use a SAML strategy
 * These may be provided by means of defaults specified in the constructor
 */
export interface SamlOptions extends Partial<SamlSigningOptions>, MandatorySamlOptions {
  // Core
  callbackUrl?: string;
  path: string;
  protocol?: string;
  host: string;
  issuer: string;
  decryptionPvk?: string | Buffer;

  // Additional SAML behaviors
  additionalParams: Record<string, string>;
  additionalAuthorizeParams: Record<string, string>;
  identifierFormat?: string | null;
  acceptedClockSkewMs: number;
  attributeConsumingServiceIndex?: string;
  disableRequestedAuthnContext: boolean;
  authnContext: string[];
  forceAuthn: boolean;
  skipRequestCompression: boolean;
  authnRequestBinding?: string;
  racComparison: RacComparision;
  providerName?: string;
  passive: boolean;
  idpIssuer?: string;
  audience?: string;
  scoping?: SamlScopingConfig;
  wantAssertionsSigned?: boolean;
  maxAssertionAgeMs: number;
  generateUniqueId: () => string;

  // InResponseTo Validation
  validateInResponseTo: boolean;
  requestIdExpirationPeriodMs: number;

  // Logout
  logoutUrl: string;
  additionalLogoutParams: Record<string, string>;
  logoutCallbackUrl?: string;

  // extras
  disableRequestAcsUrl: boolean;
}

export interface StrategyOptions {
  name?: string;
  passReqToCallback?: boolean;
}

/**
 * These options are available for configuring a SAML strategy
 */
export type SamlConfig = Partial<SamlOptions> & StrategyOptions & MandatorySamlOptions;

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
  getAssertionXml?(): string; // get the raw assertion XML
  getAssertion?(): Record<string, unknown>; // get the assertion XML parsed as a JavaScript object
  getSamlResponseXml?(): string; // get the raw SAML response XML
  [attributeName: string]: unknown; // arbitrary `AttributeValue`s
}

export class ErrorWithXmlStatus extends Error {
  constructor(message: string, public readonly xmlStatus: string) {
    super(message);
  }
}
