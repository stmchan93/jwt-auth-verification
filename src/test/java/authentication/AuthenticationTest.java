package authentication;

import authentication.model.AuthorizerResponse;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.*;

public class AuthenticationTest {

    private static final String TOKEN_WITH_KID = "eyJraWQiOiJVczFCQTZvcTk3SGFmQmVpdU43ZWxVamJPbklSM0JyMFl4dWFtYlhpbVBnPSIsImFsZyI6IlJTMjU2In0." +
            "eyJzdWIiOiJiNzgwOTYwYS00ZmZkLTRiMGMtYmFkMC00NDc1ODE4YzgyNjUiLCJhdWQiOiI2YXE4OGR0dHA2cm05YTg3" +
            "aG81OWljcGFiOSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6Ijk2MTRlM2EwLWI0NzYtNDhhYS1iMTdmL" +
            "WNjNDZhYzFkMmRlNiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTY3NzkyMTE2LCJpc3MiOiJodHRwczpcL1w" +
            "vY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9BQ2lNaEVqSmgiLCJjb2duaXRvOnVzZX" +
            "JuYW1lIjoiYjc4MDk2MGEtNGZmZC00YjBjLWJhZDAtNDQ3NTgxOGM4MjY1IiwiZXhwIjoxNTY3Nzk1NzE2LCJpYXQiOjE1Nj" +
            "c3OTIxMTYsImVtYWlsIjoid2VuYm8ubHl1QGdldHJ1YnkuaW8ifQ.qffeKpj90tT_uBte6YsPSVsnd4IFbst-7oNXZbCyusfm" +
            "aosj01EvE3MS-jc2XOJL7IieoSEwx0D7-xr6d-OfjpdEVF7gvbyZV4eGo67fT8Xm8Wm9rpl05UXdy8bpiBGfK7_rI7ixWHEKvU" +
            "MHtDlB2a_ps3NZekU3OPoWcwOD9oh-nHf4311PjewyIsaelkP1y9awtCKkUJ4bUlMk8TOlgF70YEb96vXGSi4h_TWAeBFz2TdMI9" +
            "dQNl8FBrxoJKugRgFcP13mO-bQRTSkZ4z5h1V7iPTX29S6XnhSDYUAlRReil1tWInLe41D1dsb4G84fot--OHNJQJB4ptrqFtslQ";

    private static final String TOKEN_WITHOUT_KID = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l" +
            "IiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6Afg" +
            "ZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht" +
            "0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f" +
            "4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";

    // Basic Auth header passed in
    private static final String BASIC_AUTH_ENCODED = "Basic YWRtaW46cGFzc3dvcmQ=";
    // API Id used for dummy domain name for API Gateway
    private static final String API_ID = "1mp6vmezwk";
    private static final String STAGE = "testing";
    private static final String AUTH_TOKEN_ENDPOINT = "auth/token";
    private static final String ORDER_ENDPOINT = "order";

    private Context setupContext() {
        Context context = Mockito.mock(Context.class);
        LambdaLogger logger = Mockito.mock(LambdaLogger.class);
        when(context.getLogger()).thenReturn(logger);
        return context;
    }

    @Test
    public void noKid() {
        Assert.assertNull(executeGetKid(TOKEN_WITHOUT_KID));
    }

    @Test(expected = RuntimeException.class)
    public void errorDecodingJwt() {
        Assert.assertNull(executeGetKid("1234"));
    }

    @Test
    public void kidFound() {
        Assert.assertNotNull(executeGetKid(TOKEN_WITH_KID));
    }

    @Test(expected = RuntimeException.class)
    public void errorParsingJwk() {
        Authentication authentication = new Authentication();
        Assert.assertNull(authentication.constructPublicKey(new HashMap<>(), "1234", setupContext().getLogger()));
    }

    // Claim should be expired since JWT is old
    @Test(expected = RuntimeException.class)
    public void errorVerifyingJWT() {
        Authentication authentication = new Authentication();
        authentication.handleRequest(createProxyRequest(TOKEN_WITH_KID), setupContext());
    }

    @Test(expected = RuntimeException.class)
    public void errorNullAuthorizationHeader() {
        Authentication authentication = new Authentication();
        APIGatewayProxyRequestEvent request = Mockito.mock(APIGatewayProxyRequestEvent.class);
        when(request.getHeaders()).thenReturn(createAuthorizationHeader("Authorization", null));
        authentication.findAuthorizationMethod(request, setupContext().getLogger());
    }

    @Test(expected = RuntimeException.class)
    public void errorNonBearerOrBasicAuthorizationHeader() {
        Authentication authentication = new Authentication();
        APIGatewayProxyRequestEvent request = Mockito.mock(APIGatewayProxyRequestEvent.class);
        when(request.getHeaders()).thenReturn(createAuthorizationHeader("asdf", ""));
        authentication.findAuthorizationMethod(Mockito.mock(APIGatewayProxyRequestEvent.class), setupContext().getLogger());
    }

    // TODO: fix ignore, just getting api id from proxy request
    @Test
    public void basicAuthorizationHeaderPassedIn() {
        Authentication authentication = new Authentication();
        APIGatewayProxyRequestEvent request = mockOrderApiGatewayRequestEvent(BASIC_AUTH_ENCODED, "/" + STAGE + "/" + AUTH_TOKEN_ENDPOINT);
        AuthorizerResponse response = authentication.findAuthorizationMethod(request, setupContext().getLogger());
        assertApiPolicy(response, createContext(), "Allow", AUTH_TOKEN_ENDPOINT);
    }

    // TODO: JWT authorization needs a JWT with a KID and no expiration date to write properly.
    @Test
//    @Ignore
    public void jwtExpiredAuthorizationHeaderPassedIn() {
        Authentication authentication = new Authentication();
        String authorizationValue = "Bearer " + TOKEN_WITH_KID;
        APIGatewayProxyRequestEvent request = mockOrderApiGatewayRequestEvent(authorizationValue,"/" + STAGE + "/" + ORDER_ENDPOINT);
        AuthorizerResponse response = authentication.findAuthorizationMethod(request, setupContext().getLogger());
        assertApiPolicy(response, null, "Deny", ORDER_ENDPOINT);
    }

    @Test
    public void basicAuthVerification() {
        Authentication authentication = new Authentication();
        String [] values = authentication.getCredentialsForBasicAuth(BASIC_AUTH_ENCODED);
        Assert.assertEquals("admin", values[0]);
        Assert.assertEquals("password", values[1]);
    }

    @Test(expected = RuntimeException.class)
    public void errorInvalidJwtValidation() {
        Authentication authentication = new Authentication();
        String authorizationString = "Bearer " + TOKEN_WITH_KID +"1234";
        authentication.createPolicyFromJwt(Mockito.mock(APIGatewayProxyRequestEvent.class), authorizationString, setupContext().getLogger());
    }

    // TODO: fix ignore, just getting api id from proxy request
    @Test
    public void createApiPolicyNullContext() {
        Authentication authentication = new Authentication();
        APIGatewayProxyRequestEvent request = mockOrderApiGatewayRequestEvent(BASIC_AUTH_ENCODED, "/" + STAGE + "/" + ORDER_ENDPOINT);
        AuthorizerResponse response = authentication.createApiPolicy(request, "us-east-1", "Allow", null,null, setupContext().getLogger());
        assertApiPolicy(response, null, "Allow", ORDER_ENDPOINT);
    }

    @Test
    public void getArnNoRegion() {
        Authentication authentication = new Authentication();
        String arn = authentication.createArn(null, "1", API_ID, "test", "GET", "order");
        Assert.assertEquals("arn:aws:execute-api:*:1:" + API_ID + "/test/GET/order", arn);
    }

    @Test
    public void getArnNoApiId() {
        Authentication authentication = new Authentication();
        String arn = authentication.createArn("us-east-1", "1", null, "test", "GET", "order");
        Assert.assertEquals("arn:aws:execute-api:us-east-1:1:*/test/GET/order", arn);
    }

    @Test
    public void getArnNoStage() {
        Authentication authentication = new Authentication();
        String arn = authentication.createArn("us-east-1", "1", API_ID, null, "GET", "order");
        Assert.assertEquals("arn:aws:execute-api:us-east-1:1:" + API_ID + "/*/GET/order", arn);
    }

    private Map<String, String> createContext() {
        Map<String, String> context = new HashMap<>();
        context.put("userName", "admin");
        context.put("password", "password");
        return context;
    }

    private void assertApiPolicy(AuthorizerResponse response, Map<String, String> context, String effect, String resourcePath) {
        Assert.assertEquals("123", response.getPrincipalId());
        Assert.assertEquals(context, response.getContext());
        Assert.assertEquals("execute-api:Invoke", response.getPolicyDocument().Statement.get(0).Action);
        Assert.assertEquals(effect, response.getPolicyDocument().Statement.get(0).Effect);
        Assert.assertEquals("arn:aws:execute-api:us-east-1:123:" + API_ID + "/testing/GET/" + resourcePath, response.getPolicyDocument().Statement.get(0).Resource);

    }

    /**
     * Mock an API request to the Order API gateway which has a resource path as:
     * arn:aws:execute-api:us-east-1:123:auth/token/testing/GET/order
     * @param authorizationValue
     * @return
     */
    private APIGatewayProxyRequestEvent mockOrderApiGatewayRequestEvent(String authorizationValue, String resourcePath) {
        APIGatewayProxyRequestEvent request = Mockito.mock(APIGatewayProxyRequestEvent.class);
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext = Mockito.mock(APIGatewayProxyRequestEvent.ProxyRequestContext.class);
        APIGatewayProxyRequestEvent.RequestIdentity identity = Mockito.mock(APIGatewayProxyRequestEvent.RequestIdentity.class);
        Map<String, String> stageVariables = new HashMap<>();

        stageVariables.put("region", "us-east-1");
        stageVariables.put("userPoolId", "poolId");
        when(request.getStageVariables()).thenReturn(stageVariables);

        Map<String, String> authorizationHeader = new HashMap<>();
        authorizationHeader.put("Authorization", "Bearer " + TOKEN_WITH_KID);
        when(request.getHeaders()).thenReturn(authorizationHeader);

        when(request.getRequestContext()).thenReturn(proxyRequestContext);
        when(request.getRequestContext().getIdentity()).thenReturn(identity);
        when(request.getRequestContext().getStage()).thenReturn(STAGE);
        when(request.getRequestContext().getHttpMethod()).thenReturn("GET");
        when(request.getRequestContext().getPath()).thenReturn(resourcePath);
        when(request.getRequestContext().getAccountId()).thenReturn("123");
        when(request.getRequestContext().getApiId()).thenReturn(API_ID);
        when(request.getHeaders()).thenReturn(createAuthorizationHeader("Authorization", authorizationValue));
        return request;
    }


    // TODO: JWT authorization needs a JWT with a KID and no expiration date to write properly.
    @Test
    @Ignore
    public void validateJwt() {
        Authentication authentication = new Authentication();
        authentication.handleRequest(createProxyRequest(generateJwt()), setupContext());
    }

    private Map<String, String> createAuthorizationHeader(String key, String value) {
        Map<String, String> authorizationHeader = new HashMap<>();
        authorizationHeader.put(key, value);
        return authorizationHeader;
    }

    private String generateJwt() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            Assert.fail("Error while trying to create RSA Key-Pair generation");
        }
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        Key pub = kp.getPublic();
        Key pvt = kp.getPrivate();
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) pub, (RSAPrivateKey) pvt);
        Map<String, Object> headers = new HashMap<>();
        String token = JWT.create()
                .withKeyId("Us1BA6oq97HafBeiuN7elUjbOnIR3Br0YxuambXimPg=")
                .sign(algorithm);
        return token;
    }

    private String executeGetKid(String token) {
        Authentication authentication = new Authentication();
        return authentication.getKid(token, setupContext().getLogger());
    }

    private APIGatewayProxyRequestEvent createProxyRequest(String token) {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", token);
        request.setHeaders(headers);
        return request;
    }
}
