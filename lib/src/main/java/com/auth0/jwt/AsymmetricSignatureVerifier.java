package com.auth0.jwt;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@SuppressWarnings("unused")
public class AsymmetricSignatureVerifier extends SignatureVerifier {

    public AsymmetricSignatureVerifier(JwkProvider jwkProvider) {
        super(createJWTVerifier(jwkProvider), SignatureVerifier.RS256);
    }

    private static JWTVerifier createJWTVerifier(final JwkProvider jwkProvider) {
        Algorithm alg = Algorithm.RSA256(new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                try {
                    Jwk jwk = jwkProvider.get(keyId);
                    return (RSAPublicKey) jwk.getPublicKey();
                } catch (JwkException ignored) {
                    // JwkException handled by Algorithm verify implementation from java-jwt
                }
                return null;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                //NO-OP
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                //NO-OP
                return null;
            }
        });
        return JWT.require(alg)
                .ignoreIssuedAt()
                .build();
    }
}
