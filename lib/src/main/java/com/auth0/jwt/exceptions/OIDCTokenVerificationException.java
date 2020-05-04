package com.auth0.jwt.exceptions;

public class OIDCTokenVerificationException extends JWTVerificationException {

    public OIDCTokenVerificationException(String message) {
        super(message);
    }

    public OIDCTokenVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
