const jwt = require("jsonwebtoken");

function authenticate(req) {
  const token = req.headers.authorization.replace("Bearer ", "");

  const claims = jwt.decode(token, { complete: false });

  // Vulnerable: decoded claims are trusted without signature, issuer, or
  // audience validation.
  return {
    userId: claims.sub,
    tenant: claims.tid,
    scopes: claims.scope ? claims.scope.split(" ") : []
  };
}
