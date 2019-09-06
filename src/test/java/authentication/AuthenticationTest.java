package authentication;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
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

import static org.mockito.Mockito.when;

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
        Assert.assertNull(authentication.constructPublicKey("1234", setupContext().getLogger()));
    }

    @Ignore
    @Test(expected = RuntimeException.class)
    public void errorJwkUrl() {
        // need to parameterize JWK URL
    }

    // Claim should be expired since JWT is old
    @Test(expected = RuntimeException.class)
    public void errorVerifyingJWT() {
        Authentication authentication = new Authentication();
        Event event = new Event(TOKEN_WITH_KID);
        authentication.handleRequest(event, setupContext());
    }

    // This test may not be valid because for the test to pass we need to generate a JWT with no expiration (so it passes claim verification) and there is a corresponding
    // jwt in the JWKs
    @Test
    @Ignore
    public void validateJwt() {
        Authentication authentication = new Authentication();
        Event event = new Event(generateJwt());
        authentication.handleRequest(event, setupContext());
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
        Context context = setupContext();
        return authentication.getKid(token, setupContext().getLogger());
    }
}
