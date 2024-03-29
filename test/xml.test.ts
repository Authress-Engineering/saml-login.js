import { expect } from 'chai';
import { parseDomFromString, parseXml2JsFromString, xpath } from "../src/xml";

describe("xml.ts", () => {
  it('issuer validation test', async () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="AUTHRESS_4fee3b046395c4e751011e97f8900b5273d56685">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <samlp:Status>
      <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
      <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
      <saml:Subject>
        <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="AUTHRESs_4fee3b046395c4e751011e97f8900b5273d56685"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
        <saml:AudienceRestriction>
          <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
        </saml:AudienceRestriction>
      </saml:Conditions>
      <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
        <saml:AuthnContext>
          <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
        </saml:AuthnContext>
      </saml:AuthnStatement>
      <saml:AttributeStatement>
        <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
          <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
          <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
          <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
          <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>
    </saml:Assertion>
  </samlp:Response>`;
    const doc = parseDomFromString(xml);
  
    if (!Object.prototype.hasOwnProperty.call(doc, "documentElement")) {
      throw new Error("SAMLResponse is not valid base64-encoded XML");
    }
  
    const issuersXml = xpath.selectElements(doc, "/*[local-name()='Response']/*[local-name()='Issuer']");
    const issuerResult = await parseXml2JsFromString(issuersXml.toString());
    expect(issuerResult.Issuer._).to.eql('http://idp.example.com/metadata.php');
  });
});