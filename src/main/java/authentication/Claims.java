package authentication;

public class Claims {

    private String sub;
    private Boolean emailVerified;
    private String iss;
    private String cognito;
    private String aud;
    private String eventId;
    private String tokenUse;
    private Long authTime;
    private Long exp;
    private Long iat;
    private String email;

    Claims(String sub, Boolean emailVerified, String iss, String cognito, String aud, String eventId, String tokenUse, Long authTime, Long exp, Long iat, String email) {
        this.sub = sub;
        this.emailVerified = emailVerified;
        this.iss = iss;
        this.cognito = cognito;
        this.aud = aud;
        this.eventId = eventId;
        this.tokenUse = tokenUse;
        this.authTime = authTime;
        this.exp = exp;
        this.iat = iat;
        this.email = email;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getCognito() {
        return cognito;
    }

    public void setCognito(String cognito) {
        this.cognito = cognito;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public String getTokenUse() {
        return tokenUse;
    }

    public void setTokenUse(String tokenUse) {
        this.tokenUse = tokenUse;
    }

    public Long getAuthTime() {
        return authTime;
    }

    public void setAuthTime(Long authTime) {
        this.authTime = authTime;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
