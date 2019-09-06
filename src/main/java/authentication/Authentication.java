package authentication;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;

public class Authentication implements RequestHandler<Event, Claims> {

    // TODO: parameterize region, userpool id
    private static final String REGION = "us-east-1";
    private static final String USER_POOL_ID = "us-east-1_ACiMhEjJh";
    private static final String JWK_URL = "https://cognito-idp." + REGION + ".amazonaws.com/" + USER_POOL_ID + "/.well-known/jwks.json";

    @Override
    public Claims handleRequest(Event input, Context context) throws RuntimeException {
        // TODO: figure how Event object can represent incoming requests from API Gateway. Token may also come in form of Authorization header
        LambdaLogger logger = context.getLogger();
        String token = input.getToken();
        try {
            // kid can be used to form a public key
            String kid = getKid(token, logger);
            RSAPublicKey publicKey = constructPublicKey(kid, logger);
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            logger.log("Decoding JWT and verifiying claim.\n");
            DecodedJWT decodedJWT = JWT.require(algorithm).build().verify(token);
            logger.log("JWT verified and claims returned." + "\n");
            return createClaims(decodedJWT);
        } catch (RuntimeException e) {
            // log the JWT verification exception issues
            logger.log(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }

    protected String getKid(String token, LambdaLogger logger) throws RuntimeException {
        String kid;
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            Claim claim = decodedJWT.getHeaderClaim("kid");
            if(claim.isNull()) {
                kid = null;
                logger.log("JWT Does not have claim kid");
            } else {
                kid = claim.asString();
                logger.log("Kid found: " + kid + "\n");
            }
        } catch (JWTDecodeException e) {
            logger.log("Exception decoding JWT.");
            throw new RuntimeException(e.getMessage());
        }
        return kid;
    }

    /**
     * We need to generate a public key based on the passed in kid so that the the JWT token can be verified
     * @param kid
     * @return
     */
    protected static RSAPublicKey constructPublicKey(String kid, LambdaLogger logger) throws RuntimeException {
        try {
            // TODO: parameterize JWK URL
            UrlJwkProvider urlJwkProvider = new UrlJwkProvider(new URL(JWK_URL));
            Jwk jwk = urlJwkProvider.get(kid);
            return (RSAPublicKey) jwk.getPublicKey();
        } catch (JwkException | MalformedURLException e) {
            logger.log("Exception while trying to get jwk: "+ e.getMessage() + "\n");
            throw new RuntimeException(e.getMessage());
        }
    }

    private Claims createClaims(DecodedJWT jwt) {
        return new Claims(
                jwt.getClaims().get("sub").asString(),
                jwt.getClaims().get("email_verified").asBoolean(),
                jwt.getClaims().get("iss").asString(),
                jwt.getClaims().get("cognito:username").asString(),
                jwt.getClaims().get("aud").asString(),
                jwt.getClaims().get("event_id").asString(),
                jwt.getClaims().get("token_use").asString(),
                jwt.getClaims().get("auth_time").asLong(),
                jwt.getClaims().get("exp").asLong(),
                jwt.getClaims().get("iat").asLong(),
                jwt.getClaims().get("email").asString()
        );
    }
}

