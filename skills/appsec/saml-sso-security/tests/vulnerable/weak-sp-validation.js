const samlOptions = {
  issuer: "https://sp.example.com/metadata",
  callbackUrl: "https://app.example.com/saml/acs",
  idpCert: process.env.IDP_CERT,

  // Vulnerable: accepts unsigned assertions, unsolicited responses, and very
  // wide clock skew. The SP also does not bind responses to AuthnRequest IDs.
  wantAssertionsSigned: false,
  validateInResponseTo: false,
  allowUnsolicited: true,
  acceptedClockSkewMs: 10 * 60 * 1000
};

module.exports = samlOptions;
