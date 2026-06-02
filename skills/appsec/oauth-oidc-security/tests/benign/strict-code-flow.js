const registeredRedirect = "https://app.example.com/oauth/callback";

function beginLogin(req, res) {
  const state = randomBase64Url(32);
  const nonce = randomBase64Url(32);
  const codeVerifier = randomBase64Url(64);
  const codeChallenge = sha256Base64Url(codeVerifier);

  req.session.oauth = {
    state,
    nonce,
    codeVerifier,
    redirectUri: registeredRedirect
  };

  res.redirect(buildAuthorizeUrl({
    response_type: "code",
    client_id: "web",
    redirect_uri: registeredRedirect,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256"
  }));
}

function callback(req) {
  if (req.query.state !== req.session.oauth.state) {
    throw new Error("state mismatch");
  }

  return exchangeCode({
    code: req.query.code,
    redirectUri: req.session.oauth.redirectUri,
    codeVerifier: req.session.oauth.codeVerifier,
    expectedNonce: req.session.oauth.nonce
  });
}
