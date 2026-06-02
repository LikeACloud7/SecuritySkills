const allowedRedirectPrefix = "https://app.example.com/callback";

function beginLogin(req, res) {
  const redirectUri = req.query.redirect_uri;
  const state = Math.random().toString(36).slice(2);

  if (!redirectUri.startsWith(allowedRedirectPrefix)) {
    throw new Error("redirect not allowed");
  }

  req.session.oauthState = state;
  res.redirect(
    "https://idp.example.com/authorize" +
      "?response_type=code" +
      "&client_id=web" +
      "&redirect_uri=" + encodeURIComponent(redirectUri) +
      "&state=" + state
  );
}

function callback(req, res) {
  // Vulnerable: no state comparison and no one-time transaction binding.
  exchangeCode(req.query.code);
  res.redirect("/home");
}
