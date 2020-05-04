package com.auth0.jwt;

import com.auth0.jwt.exceptions.OIDCTokenVerificationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.Validate;

import java.util.Arrays;
import java.util.List;

public abstract class SignatureVerifier {

    private final JWTVerifier verifier;
    private final List<String> acceptedAlgorithms;

    public final static String HS256 = "HS256";
    public final static String RS256 = "RS256";

    /**
     * Creates a new JWT Signature Verifier.
     * This instance will validate the token was signed using an expected algorithm
     * and then proceed to verify its signature
     *
     * @param verifier  the instance that knows how to verify the signature. When null, the signature will not be checked.
     * @param algorithm the accepted algorithms. Must never be null!
     */
    public SignatureVerifier(JWTVerifier verifier, String... algorithm) {
        Validate.notEmpty(algorithm);
        this.verifier = verifier;
        this.acceptedAlgorithms = Arrays.asList(algorithm);
    }

    private DecodedJWT decodeToken(String token) throws OIDCTokenVerificationException {
        try {
            return JWT.decode(token);
        } catch (JWTDecodeException e) {
            throw new OIDCTokenVerificationException("ID token could not be decoded", e);
        }
    }

    public DecodedJWT verifySignature(DecodedJWT token) throws OIDCTokenVerificationException {
        if (!this.acceptedAlgorithms.contains(token.getAlgorithm())) {
            throw new OIDCTokenVerificationException(String.format("Signature algorithm of \"%s\" is not supported. Expected the ID token to be signed with \"%s\".", token.getAlgorithm(), this.acceptedAlgorithms));
        }
        try {
            verifier.verify(token);
        } catch (SignatureVerificationException e) {
            throw new OIDCTokenVerificationException("Invalid token signature", e);
        } catch (JWTVerificationException ignored) {
            //NO-OP. Will be catch on a different step
            //Would only trigger for "expired tokens" (invalid exp)
        }

        return token;
    }

    public DecodedJWT verifySignature(String token) throws OIDCTokenVerificationException {
        return verifySignature(decodeToken(token));
    }
}
