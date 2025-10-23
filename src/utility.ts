import { SamlSigningOptions, SignatureTarget } from "./types";
import { signXml } from "./xml";

export function assertRequired<T>(value: T | null | undefined, error?: string): T {
  if (value === undefined || value === null || (typeof value === "string" && value.length === 0)) {
    throw new TypeError(error || "value does not exist");
  } else {
    return value;
  }
}

export function signXmlResponse(samlMessage: string, options: SamlSigningOptions): string {
  const signatureTargetXPaths = {
    [SignatureTarget.Assertion]: {
      responseXpath: "//*[local-name()='Response' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol']/*[local-name()='Assertion' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']",
      targetLocationXPath: "//*[local-name()='Response' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol']/*[local-name()='Assertion' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']/*[local-name()='Issuer' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']"
    },
    [SignatureTarget.Response]: {
      responseXpath: '//*[local-name(.)="Response" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]',
      targetLocationXPath: "//*[local-name()='Response' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol']/*[local-name()='Issuer' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']"
    }
  };

  return signXml(
    samlMessage,
    signatureTargetXPaths[options.signatureTarget].responseXpath,
    { reference: signatureTargetXPaths[options.signatureTarget].targetLocationXPath, action: "after" },
    options
  );
}
