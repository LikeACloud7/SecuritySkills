function linkExternalIdentity(profile) {
  if (!profile.email_verified) {
    throw new Error("verified email required for linking");
  }

  const namespace = `${profile.iss}:${profile.sub}`;
  const existingIdentity = findIdentityByNamespace(namespace);

  if (existingIdentity) {
    return existingIdentity.user;
  }

  const user = findOrCreateCandidateUser(profile.email);
  saveExternalIdentity({
    userId: user.id,
    issuer: profile.iss,
    subject: profile.sub,
    email: profile.email
  });

  return user;
}
