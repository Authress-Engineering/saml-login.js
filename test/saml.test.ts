import { expect } from 'chai';
import SamlLogin from '../src/saml';

describe('saml.ts', () => {
  describe('getSamlAssertionMetadata()', () => {
    it('correctly parses response assertion and correctly decodes hex characters as utf8', async () => {
      const stringRequest = 'SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIElEPSJfYTFiOWFjNjAtNTFkNi00MzcxLTkzZDAtMTdhZGY0ZDM0YWNhIiBJblJlc3BvbnNlVG89IllYQXRaV0Z6ZEh4aGRYUm9jbVZ6Y3k1cGIzdzNZakkxTnpkak1HVTJPVFl4TVdWbE9HVmlaV016WmpBME9HVmxPR0l5TW53LTVka2F0bEZkUllwZ3FPMGZzNlFDODd5VU5sWTZZNk9Pb2hjQnVEeUUxWkM2RFBkVkRNRVVJMFFpbU5kb2gzamNFdmZfQ3BjcFNHMXNNUUxaYUNlOGZBX3gwMDdFX2N5YmVyYXJrLmNvbS5hcGkuYXV0aHJlc3MuaW8iIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDI0LTAzLTIwVDA4OjQ3OjMwLjA5OVoiIERlc3RpbmF0aW9uPSJodHRwczovL2xvZ2luLmF1dGhyZXNzLmlvL2FwaS9hdXRoZW50aWNhdGlvbi9zYW1sIiB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI%2BPElzc3VlciB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI%2BaHR0cHM6Ly9hYWs3MzI4Lm15LmRldi5pZGFwdGl2ZS5hcHAvMDZhZWYxNjEtM2I1Mi00NTE4LWJiOTQtNzY5ZmQ1MTkwMTdkPC9Jc3N1ZXI%2BPFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI%2BPFNpZ25lZEluZm8%2BPENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIC8%2BPFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiIC8%2BPFJlZmVyZW5jZSBVUkk9IiNfYTFiOWFjNjAtNTFkNi00MzcxLTkzZDAtMTdhZGY0ZDM0YWNhIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiIC8%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIgLz48L1RyYW5zZm9ybXM%2BPERpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIgLz48RGlnZXN0VmFsdWU%2BaVQ3SGhuRndockorR0ZDVmlxL0RPLzNhL1pDNVNzM29kVUQ3VWJVMUpqcz08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU%2BT0dYZzIxRWhZSUtnUkRrQ1QxMERsM29va0VZTkdGUjc3R2wyVXF2dUZBUnRWd0dpZ1ZSbkxrd0pRaFlwM3hxSzNIZTFydHRtQ3VxaDB4Nk1PVmpvRHkyQW05dmVpY1V6REtMRUxGY2x0Y21YR3RwbjNNUDc5bGJrUWNaM1BiakdvTEhBbEw1S2pjYnc4a1pKKzZoK1pnTVBCZVRzNFYvck1PU1pHTTBvZXZkdURPRHpXN1FTSmlIZVBMUmJDYnI1SUtieEJVVzNqK0tNUlpSUlpyQTZXbWVSUmErTkxxMmloTFl1RFlBdEYwUnV6c2F5eEd2N0R4NFYwcitENXFnY2ZqS0huZkZ2cG9CSGw4VkpuTlRYR0s3eTBZSG1ETXFXQitueWl3U3psamR3RUhNQWpkVnNpeHJQV29KSFBTUnJJZWhseVJwc3hxWU93MVZCNEVsdmRBPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURrekNDQW4yZ0F3SUJBZ0lRRythUjBhQk12MEdHcmFLS0UxL2hDVEFMQmdrcWhraUc5dzBCQVFzd0pERWlNQ0FHQTFVRUF3d1pTV1JoY0hScGRtVWdRM1Z6ZEc5dFpYSWdRVUZMTnpNeU9EQWVGdzB5TVRFd01ESXhNVFE0TUROYUZ3MHpPVEF4TURFd01EQXdNREJhTURJeE1EQXVCZ05WQkFNTUowRkJTemN6TWpnZ1FYQndiR2xqWVhScGIyNGdVMmxuYm1sdVp5QkRaWEowYVdacFkyRjBaVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNekVhSTdlckxORXFEaEZXeDNUT0pLdlcrcS9Ta3E0dmcwclpMd2V1amRpSDJPcVFzRFFtVlQ0THM4R2VHRFVLRWNOMmtxL0FnYXV3UHFOZk5EeHZ2N25lRkFSN3cyMnBSWXZnaERkQWcwQXNFeU4xQ0xxMXl5aG5CY21EMnE2eTJzTVVZMzVrcG93NkZENGJOOXdoL3JQT3B3YzRUeEQ4VGptS1NDamQzeVlkOTQwNUtzemJuS2lZNnFKK0drR0M1Q1czYlZXa051T1Z5VWJJc3c0TFVmbkdzWE9xcFBqYTNUUnk3NmI5TzE3T2dFYytKeERDY3QvNEJtdUZ5SkJNYWJPbVFmTVBnYkhiN1Avak1HVEZWMDQ4YlFoTG92c0RzUDNZV0RlTmtUcjVYS3p6K0xRNmFGazRQb1ZXTTFQcmpjVWtVQTNBMlRuWnBhUlZ4cGE5UzBDQXdFQUFhT0J0akNCc3pBVEJnb3JCZ0VFQVlLbWNBRUpCQVVNQXpFdU1EQVhCZ29yQmdFRUFZS21jQUVEQkFrTUIwRkJTemN6TWpnd0t3WURWUjBqQkNRd0lvQWdCbUJ3Z0VPTGFFTitOMGZyeWdqSlZoUEJiL2dBeC9Wd0ZmMFFHRUphbzBnd0tRWURWUjBPQkNJRUlMK3BIdnlROGtBUXBWVnBuVGg5cEFQTExpaWU5Ynd1S1ZNRHpnMHA5UXpwTUE0R0ExVWREd0VCL3dRRUF3SUZvREFiQmdvckJnRUVBWUttY0FFRUJBME1DMEZ3Y0d4cFkyRjBhVzl1TUFzR0NTcUdTSWIzRFFFQkN3T0NBUUVBVDRFakhLNFM2QlFCRlNrZG5GZTA4NVpUYzd6QnVLeGhSWUMrMGx1aC9YTXFFeHIxUHgrY0l3TkRaSlJXaWpLRWNpSmFUekJudFVhbDV4NmJ2K0psMFNHdjhBaEVTYVl2ZUxVWHNqUkgvUkNJM0FyNTFPWWtzb0luSEpDVlZlUFNFTkNQU2xkWnEzMEsyMTRWbmJUWVJUWU04dDFEZUlxRWMvY25rWmllY1FTSHA4SVY5akJ1TEdmd2Uxa3VmWG54OGthUkJ2cnlqZjVrbGJROFpyanRFUXZpVUI4VkI3S2JXV1pvOS9GNUdQODk5NkI0eGplUGxwYmZRUVYrWjVlc3BOZExrUnNzYUlRUkt6dTc5bFFSWVNKc0luMUU3MmJKLzl4VWhKMXFOcElhM3hIZ0RGeGc2Y0NraDBsRCtsM05ZcVNSdWtURVVZeks5T3JFYzgzdUxRPT08L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbDJwOlN0YXR1cz48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIgLz48L3NhbWwycDpTdGF0dXM%2BPEFzc2VydGlvbiBWZXJzaW9uPSIyLjAiIElEPSJfMmIzMzVkZjctMTNjZS00ZTRkLWE0NjUtMDUyYzRmNWFlODNkIiBJc3N1ZUluc3RhbnQ9IjIwMjQtMDMtMjBUMDg6NDc6MzAuMDYyWiIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxJc3N1ZXI%2BaHR0cHM6Ly9hYWs3MzI4Lm15LmRldi5pZGFwdGl2ZS5hcHAvMDZhZWYxNjEtM2I1Mi00NTE4LWJiOTQtNzY5ZmQ1MTkwMTdkPC9Jc3N1ZXI%2BPFN1YmplY3Q%2BPE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj5hcHBzYWNjb3VudHNAY3liZXJhcmsuY29tPC9OYW1lSUQ%2BPFN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDI0LTAzLTIwVDA5OjQ3OjMwLjA2MloiIFJlY2lwaWVudD0iaHR0cHM6Ly9sb2dpbi5hdXRocmVzcy5pby9hcGkvYXV0aGVudGljYXRpb24vc2FtbCIgSW5SZXNwb25zZVRvPSJZWEF0WldGemRIeGhkWFJvY21WemN5NXBiM3czWWpJMU56ZGpNR1UyT1RZeE1XVmxPR1ZpWldNelpqQTBPR1ZsT0dJeU1udy01ZGthdGxGZFJZcGdxTzBmczZRQzg3eVVObFk2WTZPT29oY0J1RHlFMVpDNkRQZFZETUVVSTBRaW1OZG9oM2pjRXZmX0NwY3BTRzFzTVFMWmFDZThmQX5jeWJlcmFyay5jb20uYXBpLmF1dGhyZXNzLmlvIiAvPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q%2BPENvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDI0LTAzLTIwVDA4OjQ0OjMwLjA2MloiIE5vdE9uT3JBZnRlcj0iMjAyNC0wMy0yMFQwOTo0NzozMC4wNjJaIj48QXVkaWVuY2VSZXN0cmljdGlvbj48QXVkaWVuY2U%2BaHR0cHM6Ly9sb2dpbi5hdXRocmVzcy5pbzwvQXVkaWVuY2U%2BPC9BdWRpZW5jZVJlc3RyaWN0aW9uPjwvQ29uZGl0aW9ucz48QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDI0LTAzLTIwVDA4OjQ3OjMwLjA2MloiIFNlc3Npb25JbmRleD0iXzJiMzM1ZGY3LTEzY2UtNGU0ZC1hNDY1LTA1MmM0ZjVhZTgzZCI%2BPEF1dGhuQ29udGV4dD48QXV0aG5Db250ZXh0Q2xhc3NSZWY%2BdXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6dW5zcGVjaWZpZWQ8L0F1dGhuQ29udGV4dENsYXNzUmVmPjwvQXV0aG5Db250ZXh0PjwvQXV0aG5TdGF0ZW1lbnQ%2BPC9Bc3NlcnRpb24%2BPC9zYW1sMnA6UmVzcG9uc2U%2B';
      
      const expectedResult = 'YXAtZWFzdHxhdXRocmVzcy5pb3w3YjI1NzdjMGU2OTYxMWVlOGViZWMzZjA0OGVlOGIyMnw-5dkatlFdRYpgqO0fs6QC87yUNlY6Y6OOohcBuDyE1ZC6DPdVDMEUI0QimNdoh3jcEvf_CpcpSG1sMQLZaCe8fA~cyberark.com.api.authress.io';
      const result = await new SamlLogin().getSamlAssertionMetadata(stringRequest);
      expect(result.authenticationRequestId).to.eql(expectedResult);
    });
  });
  describe('parseSamlRequestMetadata()', () => {
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
    });
  });
});