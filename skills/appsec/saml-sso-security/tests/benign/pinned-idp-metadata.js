const samlTrust = {
  spEntityId: "https://sp.example.com/metadata",
  assertionConsumerServiceUrl: "https://app.example.com/saml/acs",
  idpEntityId: "https://idp.example.com/metadata",
  idpSigningCertificateFingerprint: "7A:91:34:AF:50:B2:6D:4B:63:19:11:04:8C:55:AA:DE:01:6C:20:9B",
  requireSignedAssertions: true,
  requireSignedAuthnRequests: true,
  metadataRefresh: {
    source: "admin-upload",
    requiresApproval: true,
    auditEvent: "saml.metadata.updated"
  }
};

module.exports = samlTrust;
