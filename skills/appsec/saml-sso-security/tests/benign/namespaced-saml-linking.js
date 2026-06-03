function linkSamlUser(assertion) {
  const identity = {
    idpEntityId: assertion.issuer,
    nameId: assertion.subject.nameId,
    nameIdFormat: assertion.subject.nameIdFormat
  };

  const existing = findFederatedIdentity(identity.idpEntityId, identity.nameId);
  if (existing) {
    return existing.user;
  }

  const user = createUserFromApprovedSamlAttributes({
    email: assertion.attributes.email,
    displayName: assertion.attributes.displayName
  });

  saveFederatedIdentity({ userId: user.id, ...identity });
  return user;
}
