const expected = {
  idpEntityId: "https://idp.example.com/metadata",
  spEntityId: "https://sp.example.com/metadata",
  acsUrl: "https://app.example.com/saml/acs"
};

function validateAssertion(response, requestId) {
  const assertion = verifySignedAssertion(response, {
    trustedIssuer: expected.idpEntityId,
    trustedCertificateFingerprint: getPinnedIdpFingerprint(),
    requireSignedAssertion: true
  });

  requireEqual(response.destination, expected.acsUrl);
  requireEqual(assertion.subjectConfirmation.recipient, expected.acsUrl);
  requireEqual(assertion.audience, expected.spEntityId);
  requireEqual(assertion.inResponseTo, requestId);
  rejectIfReplay(assertion.id, assertion.notOnOrAfter);
  enforceTimeWindow(assertion.notBefore, assertion.notOnOrAfter, { skewSeconds: 120 });

  return assertion;
}
