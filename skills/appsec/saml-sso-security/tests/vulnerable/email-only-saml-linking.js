function linkSamlUser(assertion) {
  const email = assertion.attributes.email;
  const user = findUserByEmail(email);

  if (user) {
    // Vulnerable: any trusted IdP that can assert this email can link to the
    // same local account. The IdP entity ID and NameID are not stored.
    user.samlLogin = { email };
    return user;
  }

  return createUser({ email });
}
