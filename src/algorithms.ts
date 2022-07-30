import * as crypto from "crypto";

export function getSigningAlgorithm(shortName?: string): string {
  switch (shortName) {
    case "sha1":
      return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    case "sha512":
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    case "sha256":
    default:
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  }
}

export function getDigestAlgorithm(shortName?: string): string {
  switch (shortName) {
    case "sha1":
      return "http://www.w3.org/2000/09/xmldsig#sha1";
    case "sha512":
      return "http://www.w3.org/2001/04/xmlenc#sha512";
    case "sha256":
    default:
      return "http://www.w3.org/2001/04/xmlenc#sha256";
  }
}

export function getSigner(shortName?: string): crypto.Signer {
  switch (shortName) {
    case "sha1":
      return crypto.createSign("RSA-SHA1");
    case "sha512":
      return crypto.createSign("RSA-SHA512");
    case "sha256":
      default:
      return crypto.createSign("RSA-SHA256");
  }
}
