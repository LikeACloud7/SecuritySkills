const expectedIssuer = "https://idp.example.com/";
const expectedAudience = "https://api.example.com";

async function authorizeApiRequest(req) {
  const token = req.headers.authorization.replace("Bearer ", "");
  const claims = await verifyJwt(token, {
    issuer: expectedIssuer,
    audience: expectedAudience,
    algorithms: ["RS256"]
  });

  if (!claims.sub || !claims.scope.split(" ").includes("orders:read")) {
    throw new Error("insufficient delegated authorization");
  }

  return {
    principal: `${claims.iss}:${claims.sub}`,
    scopes: claims.scope.split(" ")
  };
}
