import * as crypto from "crypto";

export const keyToPEM = (key: string): typeof key extends string | Buffer ? string | Buffer : Error => {
  const bufferedKey = Buffer.from(key.replace(/[ \t\f]/g, '').replace(/-{5}.*-{5}/g, '').replace(/\r?\n/g, ''), 'base64');
  const keyObject = crypto.createPrivateKey({ key: bufferedKey, format: 'der', type: 'pkcs8' })
  return keyObject.export({ format: 'pem', type: 'pkcs8' });
};

export const certToPEM = (cert: string): string => {
  if (cert.indexOf("-BEGIN CERTIFICATE-") !== -1 && cert.indexOf("-END CERTIFICATE-") !== -1) {
    return cert.replace(/[ \t\f]/g, '').replace('BEGINCERTIFICATE', 'BEGIN CERTIFICATE').replace('ENDCERTIFICATE', 'END CERTIFICATE');
  }
  cert = cert.match(/.{1,64}/g)!.join("\n");

  if (cert.indexOf("-BEGIN CERTIFICATE-") === -1) cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  if (cert.indexOf("-END CERTIFICATE-") === -1) cert = cert + "\n-----END CERTIFICATE-----\n";

  return cert;
};

export const generateUniqueId = (): string => {
  return "_" + crypto.randomBytes(64).toString("hex");
};

export const removeCertPEMHeaderAndFooter = (certificate: string): string => {
  certificate = certificate.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "");
  certificate = certificate.replace(/-+END CERTIFICATE-+\r?\n?/, "");
  certificate = certificate.replace(/\r\n/g, "\n");
  return certificate;
};
