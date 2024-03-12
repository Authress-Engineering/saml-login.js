import { expect } from 'chai';
import SamlLogin from '../src/saml';

describe('saml.ts', () => {
  it('parseSamlRequest', async () => {
    const date = new Date();
    const identityProviderIssuerUrl = "https://Account-Id.login.authress.io/api/authentication/saml?appId=applicationId";
    const requestingApplicationUrl = "https://api.staging.application.com/api/saml/authress/callback";
    const applicationEntityId = 'https://applicationIdentityId';

    const samlRequestUrl = await new SamlLogin().generateAuthenticationUrl({
      providerSingleSignOnUrl: identityProviderIssuerUrl,
      requestTimestamp: date,
      applicationEntityId: applicationEntityId,
      applicationCallbackAssertionConsumerServiceUrl: requestingApplicationUrl,
      allowCreate: true
    });

    const samlRequest = new URL(samlRequestUrl).search.toString();
    const result = await new SamlLogin().parseSamlRequestMetadata(samlRequest);
    const expectedResult = {
      requestedIssuerEntityId: identityProviderIssuerUrl,
      applicationEntityId: applicationEntityId,
      applicationAssertionConsumerServiceUrl: requestingApplicationUrl,
      requestTimestap: date
    };
    expect(result).to.eql(expectedResult);
  });

  it('correctly parses valid saml request', async () => {
    const samlRequestString = 'fVNNb+IwEL33V6DcyRcJtBZEYmE/kChEkO5hLyvjDMTaxM56nJb++7UTaOmqii9Wxm/evHkzmSKtyprMG12IHfxtAPXdwJxzVQok7ePMaZQgkiJHImgFSDQj+/njmoSuT2oltWSydP5L68+iiKA0l6JLWy1nznbzdb39vtr8fphEcRwf/VEwio8smozvgzwMfD9gEDP/cJ+PJ34IftSl/gSFhmfmGNoukir5zHNQG1N15jwCFsWlCmIDK4GaCm3wfhgN/dEwCLMgIFFIgvGvDrc0JnBBdUtbaF0j8TzK2DCUnLHzqICHc87dUp64cKlxTgGiy6VHa+7ZbxCaszbfs1a8yWqN+sJFzsWp359DB0LyI8vSYbrdZx3J/OrbQgpsKlB7UM+cwdNufSO15q5p0qg7uZVt32WyasVZNd5VscdoWR4o++MkLffUvpLWJJX0c33gmXq3ie9UNbETWC1TWXL22sbt+SZVRXV/+zbC8+GxhZLajhi1cdV5Y5mXpXxZKKDazFirBpyB96H2ZZkhb1fb2KXhrAcLWdVUcbSThTNl+tL7e/+38EVp9nQHx6R3lRlhFmfCqblepMrtqIGZ2pmiAmup9MWjT8k71V6P7OTu+nz7nyb/AA==';

    const samlRequest = new URLSearchParams({ SAMLRequest: samlRequestString });
    const result = await new SamlLogin().parseSamlRequestMetadata(samlRequest.toString());
    expect(result).not.to.eql(null);
  })
});