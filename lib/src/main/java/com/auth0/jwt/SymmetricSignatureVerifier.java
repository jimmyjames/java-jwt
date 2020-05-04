package com.auth0.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;

@SuppressWarnings("unused")
public class SymmetricSignatureVerifier extends SignatureVerifier {

    public SymmetricSignatureVerifier(String secret) {
        super(createJWTVerifier(secret), "HS256");
    }

    private static JWTVerifier createJWTVerifier(String secret) {
        Algorithm alg = Algorithm.HMAC256(secret);
        return JWT.require(alg)
                .ignoreIssuedAt()
                .build();
    }
}
