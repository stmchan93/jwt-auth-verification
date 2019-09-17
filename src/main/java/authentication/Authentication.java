package authentication;

import authentication.model.AuthorizerResponse;
import authentication.model.PolicyDocument;
import authentication.model.Statement;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.util.StringUtils;
import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Authentication implements RequestHandler<APIGatewayProxyRequestEvent, AuthorizerResponse> {

    private static String EFFECT_ALLOW = "Allow";
    private static String EFFECT_DENY = "Deny";
    private static String BEARER_HEADER = "Bearer ";
    private static String BASIC_HEADER = "Basic ";
    private static String AUTHORIZATION = "Authorization";


    @Override
    public AuthorizerResponse handleRequest(APIGatewayProxyRequestEvent request, Context context) throws RuntimeException {
        // TODO: figure how Event object can represent incoming requests from API Gateway. Token may also come in form of Authorization header
        LambdaLogger logger = context.getLogger();
        return findAuthorizationMethod(request, logger);
    }

    protected AuthorizerResponse createApiPolicy(APIGatewayProxyRequestEvent request, String region, String effect, String jwtSubject, Map<String, String> context, LambdaLogger logger) {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyContext = request.getRequestContext();
        // don't use  parameterized api id for now

        String resourcePath = proxyContext.getPath().substring(proxyContext.getStage().length() + 2);
        logger.log("Resource Path: " + resourcePath);
        String arn = createArn(region, proxyContext.getAccountId(), proxyContext.getApiId(), proxyContext.getStage(), proxyContext.getHttpMethod(), resourcePath);

        Statement statement = Statement.builder()
                .action("execute-api:Invoke")
                .effect(effect)
                .resource(arn)
                .build();

        PolicyDocument policyDocument = PolicyDocument.builder()
                .statements(
                        Collections.singletonList(statement)
                ).build();

        AuthorizerResponse response = AuthorizerResponse.builder()
                .principalId(jwtSubject == null ? proxyContext.getAccountId() : jwtSubject)
                .policyDocument(policyDocument)
                .context(context)
                .build();

        // Just for logging purposes, remove this
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        String responseJson = "";
        try {
            responseJson = mapper.writeValueAsString(response);
        } catch (JsonProcessingException e) {
            logger.log("Couldn't parse json correctly, " + e.getMessage());
        }
        logger.log("Authorizer Response: " + responseJson);
        return response;
    }

    protected AuthorizerResponse findAuthorizationMethod(APIGatewayProxyRequestEvent request, LambdaLogger logger) throws RuntimeException {
        Map<String, String> headers = request.getHeaders();
        String authorizationHeader = headers.get(AUTHORIZATION);
        String region = request.getStageVariables().get("region");
        if(authorizationHeader == null && (!authorizationHeader.contains(BASIC_HEADER) || !authorizationHeader.contains(BEARER_HEADER))) {
            logger.log("Authorization must be contained in header.");
            // deny all API access if authorization is not contained in the header
            return createApiPolicy(request, region, "*", EFFECT_DENY, null, logger);
        } else if(authorizationHeader.contains("Basic ")) {
            // get user credentials
            logger.log("Authorizing through Basic Authentication");
            String [] values = getCredentialsForBasicAuth(authorizationHeader);
            // Give policy access to to authorization service for authentication to get JWT token
            // TODO: Remove this for basic authentication, just testing it out
            if(!values[0].equals("admin") || !values[1].equals("password")) {
                logger.log("Unauthorized. Wrong username & password.");
                // deny access to auth/token API
                return createApiPolicy(request, region, EFFECT_DENY, null, null, logger);
            }
            Map<String, String> context = new HashMap<>();
            context.put("userName", values[0]);
            context.put("password", values[1]);
            // we need to pass down context as a parameter to the auth/token API
            return createApiPolicy(request, region, EFFECT_ALLOW, null, context, logger);
        } else {
            logger.log("Authorizing through Bearer Token");
            return createPolicyFromJwt(request, authorizationHeader, logger);
        }
    }

    protected AuthorizerResponse createPolicyFromJwt(APIGatewayProxyRequestEvent request, String authorizationHeader, LambdaLogger logger) {
        try {
            String region = request.getStageVariables().get("region");
            String token = authorizationHeader.substring(BEARER_HEADER.length());
            String kid = getKid(token, logger);
            RSAPublicKey publicKey = constructPublicKey(request.getStageVariables(), kid, logger);
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            logger.log("Decoding JWT and verifiying claim.\n");
            DecodedJWT decodedJWT = JWT.require(algorithm).build().verify(token);
            logger.log("JWT verified. Creating API Policy.\n");
            // TODO: Get TenantId and pass it into Context
            return createApiPolicy(request, region, EFFECT_ALLOW, decodedJWT.getSubject(), null, logger);
        } catch(RuntimeException e) {
            // log the JWT verification exception issues
            logger.log(e.getMessage());
            return createApiPolicy(request, request.getStageVariables().get("region"), EFFECT_DENY, null, null, logger);
        }
    }

    protected String [] getCredentialsForBasicAuth(String authorizationHeader) {
        String encodedCredentials = authorizationHeader.substring("Basic ".length());
        byte[] decodedCredentials = Base64.getDecoder().decode(encodedCredentials);
        String credentials = new String(decodedCredentials, StandardCharsets.UTF_8);
        final String[] values = credentials.split(":", 2);
        return values;
    }

    protected String createArn(String region, String awsAccountId, String apiId, String stage, String verb, String resource) {
        if(StringUtils.isNullOrEmpty(apiId)) {
            apiId = "*";
        }
        if(StringUtils.isNullOrEmpty(region)) {
            region = "*";
        }
        if(StringUtils.isNullOrEmpty(stage)) {
            stage = "*";
        }
        String arn = String.format("arn:aws:execute-api:%s:%s:%s/%s/%s/%s",
                region,
                awsAccountId,
                // don't use  parameterized api id for now
                apiId,
                stage,
                verb,
                resource);
        return arn;
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
    protected static RSAPublicKey constructPublicKey(Map<String, String> stageVariables, String kid, LambdaLogger logger) throws RuntimeException {
        try {
            String region = stageVariables.get("region");
            String userPoolId = stageVariables.get("userPoolId");
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

