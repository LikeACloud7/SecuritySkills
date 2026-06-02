function linkExternalIdentity(profile) {
  const user = findUserByEmail(profile.email);

  if (user) {
    // Vulnerable: email alone is treated as durable identity. The issuer and
    // provider subject are not stored as a namespace, and email verification is
    // not checked before linking.
    user.externalLogin = {
      email: profile.email,
      displayName: profile.name
    };
    return user;
  }

  return createUser({ email: profile.email });
}
