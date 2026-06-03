function handleSamlResponse(xmlDocument) {
  const signedNode = validateXmlSignature(xmlDocument);
  if (!signedNode) {
    throw new Error("invalid signature");
  }

  // Vulnerable: this consumes the first Assertion in the document, which may
  // not be the signed Assertion that validateXmlSignature returned.
  const assertion = xmlDocument.getElementsByTagName("Assertion")[0];
  const nameId = assertion.getElementsByTagName("NameID")[0].textContent;

  return createSession({ subject: nameId });
}
