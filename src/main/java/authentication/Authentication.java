package authentication;

import authentication.model.AuthorizerResponse;
import authentication.model.PolicyDocument;
import authentication.model.Statement;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Authentication implements RequestHandler<APIGatewayProxyRequestEvent, AuthorizerResponse> {

    @Override
    public AuthorizerResponse handleRequest(APIGatewayProxyRequestEvent request, Context context) throws RuntimeException {
        // TODO: figure how Event object can represent incoming requests from API Gateway. Token may also come in form of Authorization header
        LambdaLogger logger = context.getLogger();
        Map<String, String> params = request.getQueryStringParameters();
        try {
            String token = getAuthorizationHeader(request, logger);
            // kid can be used to form a public key
            String kid = getKid(token, logger);
            RSAPublicKey publicKey = constructPublicKey(params, kid, logger);
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            logger.log("Decoding JWT and verifiying claim.\n");
            JWT.require(algorithm).build().verify(token);
            logger.log("JWT verified. Creating API Policy.\n");
            return createApiPolicy(request, params.get("region"));
        } catch (RuntimeException e) {
            // log the JWT verification exception issues
            logger.log(e.getMessage());
            throw e;
        }
    }

    protected AuthorizerResponse createApiPolicy(APIGatewayProxyRequestEvent request, String region) {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyContext = request.getRequestContext();
        APIGatewayProxyRequestEvent.RequestIdentity identity = proxyContext.getIdentity();

        String arn = String.format("arn:aws:execute-api:%s:%s:%s/%s/%s/%s",
                region,
                proxyContext.getAccountId(),
                proxyContext.getApiId(),
                proxyContext.getStage(),
                proxyContext.getHttpMethod(),
                "*");

        Statement statement = Statement.builder()
                .action("execute-api:Invoke")
                .effect("Allow")
                .resource(arn)
                .build();

        PolicyDocument policyDocument = PolicyDocument.builder()
                .statements(
                        Collections.singletonList(statement)
                ).build();

        Map<String, String> ctx = new HashMap<>();

        // can customize api policies
        ctx.put("username", "wenbo.lyu@getruby.io");

        return AuthorizerResponse.builder()
                .principalId(identity.getAccountId())
                .policyDocument(policyDocument)
                .context(ctx)
                .build();
    }

    protected String getAuthorizationHeader(APIGatewayProxyRequestEvent request, LambdaLogger logger) throws RuntimeException {
        Map<String, String> headers = request.getHeaders();
        String authorization = headers.get("Authorization");
        if(authorization == null) {
            throw new RuntimeException("No JWT Token found in Authorization header.");
        }
        return authorization.substring("Bearer ".length());
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
    protected static RSAPublicKey constructPublicKey(Map<String, String> params, String kid, LambdaLogger logger) throws RuntimeException {
        try {
            String region = params.get("region");
            String userPoolId = params.get("userPoolId");
            String jwkUrl = "https://cognito-idp." + region + ".amazonaws.com/" + userPoolId + "/.well-known/jwks.json";
            UrlJwkProvider urlJwkProvider = new UrlJwkProvider(new URL(jwkUrl));
            Jwk jwk = urlJwkProvider.get(kid);
            return (RSAPublicKey) jwk.getPublicKey();
        } catch (JwkException | MalformedURLException e) {
            logger.log("Exception while trying to get jwk.\n");
            throw new RuntimeException(e.getMessage());
        }
    }
}

