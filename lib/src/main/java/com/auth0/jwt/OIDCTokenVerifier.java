package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.apache.commons.lang3.Validate;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * The OIDCTokenVerifier class provides validation for OIDC-compliant ID tokens, according to the
 * <a href="https://openid.net/specs/openid-connect-core-1_0-final.html#IDTokenValidation">OIDC Specification</a>.
 *
 * <p>Supported signing algorithms are <strong>HS256</strong> and <strong>RS256</strong>.</p>
 *
 * <p>Some customizations to the verification is supported, such as a custom leeway to accommodate system clock skews:</p>
 *
 * <pre>
 * {@code
 *  OIDCTokenVerifier.init("issuer", "audience", verifier)
 *      .withClockSkew(120) // leeway for time-based verifications of 120 seconds
 *      .withMaxAge(60 * 60 * 4) // Maximum time since last authentication allowed of four hours (in seconds)
 *      .withNonce("nonce") // expected nonce on the token
 *      .build()
 *      .verify("oidc-id-token");
 * }
 * </pre>
 *
 * @see SignatureVerifier
 */
public class OIDCTokenVerifier implements JWTVerifier {

    // default clock skew of one minute.
    private static final Integer DEFAULT_CLOCK_SKEW = 60;

    private final Options verifyOptions;

    private OIDCTokenVerifier(Options verifyOptions) {
        this.verifyOptions = verifyOptions;
    }

    /**
     * Initialize a {@linkplain Builder} used to configure the instantiation of this class.
     *
     * @param issuer the expected issuer of the token. Must not be null.
     * @param audience the expected audience of the token. Must not be null.
     * @param verifier the verifier to use for token signature verification. Must not be null.
     *
     * @see SignatureVerifier
     * @return A {@linkplain Builder} for further configuration.
     */
    public static Builder init(String issuer, String audience, SignatureVerifier verifier) {
        return new Builder(issuer, audience, verifier);
    }

    /**
     * Builder to create an instance of a {@linkplain OIDCTokenVerifier}
     */
    public static class Builder {

        private final String issuer;
        private final String audience;
        private final SignatureVerifier verifier;

        private Integer maxAge;
        private String nonce;
        private Date clock;
        private Integer clockSkew;

        /**
         * Initialize the builder with required parameters.
         *
         * @param issuer the expected issuer of the token. Must not be null.
         * @param audience the expected audience of the token. Must not be null.
         * @param verifier the verifier to use for token signature verification. Must not be null.
         *
         * @see SignatureVerifier
         */
        Builder(String issuer, String audience, SignatureVerifier verifier) {
            Validate.notNull(issuer);
            Validate.notNull(audience);
            Validate.notNull(verifier);

            this.issuer = issuer;
            this.audience = audience;
            this.verifier = verifier;
        }

        /**
         * Set the maximum allowable time since last end-user authentication, in seconds, that a token is valid for.
         *
         * @param maxAge the number of seconds since last end-user authentication allowable.
         *
         * @return this Builder instance for further configuration.
         */
        public Builder withMaxAge(Integer maxAge) {
            this.maxAge = maxAge;
            return this;
        }

        /**
         * Set the expected value of the {@code nonce} claim on the token.
         *
         * @param nonce The nonce expected on the token.
         *
         * @return this Builder instance for further configuration.
         */
        public Builder withNonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        // TODO - package-private, but should see if it makes more sense to only expose it on the verifier
        Builder withClock(Date clock) {
            this.clock = clock;
            return this;
        }

        /**
         * Sets the allowable time, in seconds, that is acceptable for date/time-based claims such as {@code exp} and
         * {@code auth_time}.
         *
         * <p>The default allowable clock skew is <strong>60 seconds</strong>.</p>
         *
         * @param clockSkew the number of seconds
         *
         * @return this Builder instance for further configuration.
         */
        public Builder withClockSkew(Integer clockSkew) {
            this.clockSkew = clockSkew;
            return this;
        }

        /**
         * Build an {@linkplain OIDCTokenVerifier} using the values configured for this builder.
         *
         * @return the configured {@linkplain OIDCTokenVerifier} instance.
         */
        public OIDCTokenVerifier build() {
            Options opts = new Options(issuer, audience, verifier);
            opts.setMaxAge(maxAge);
            opts.setNonce(nonce);
            opts.setClockSkew(clockSkew);
            opts.setClock(clock);
            return new OIDCTokenVerifier(opts);
        }
    }

    @Override
    public DecodedJWT verify(String token) throws JWTVerificationException {
        if (isEmpty(token)) {
            throw new JWTVerificationException("ID token is required but missing");
        }

        DecodedJWT decoded = verifyOptions.verifier.verifySignature(token);
        verifyClaims(decoded);
        return decoded;
    }

    @Override
    public DecodedJWT verify(DecodedJWT decoded) throws JWTVerificationException {
        if (decoded == null) {
            throw new JWTVerificationException("ID token is required but missing");
        }

        verifyOptions.verifier.verifySignature(decoded);
        verifyClaims(decoded);
        return decoded;
    }

    private void verifyClaims(DecodedJWT decoded) throws JWTVerificationException {
        if (isEmpty(decoded.getIssuer())) {
            throw new JWTVerificationException("Issuer (iss) claim must be a string present in the ID token");
        }
        if (!decoded.getIssuer().equals(verifyOptions.issuer)) {
            throw new JWTVerificationException(String.format("Issuer (iss) claim mismatch in the ID token, expected \"%s\", found \"%s\"", verifyOptions.issuer, decoded.getIssuer()));
        }

        if (isEmpty(decoded.getSubject())) {
            throw new JWTVerificationException("Subject (sub) claim must be a string present in the ID token");
        }

        final List<String> audience = decoded.getAudience();
        if (audience == null) {
            throw new JWTVerificationException("Audience (aud) claim must be a string or array of strings present in the ID token");
        }
        if (!audience.contains(verifyOptions.audience)) {
            throw new JWTVerificationException(String.format("Audience (aud) claim mismatch in the ID token; expected \"%s\" but found \"%s\"", verifyOptions.audience, decoded.getAudience()));
        }

        final Calendar cal = Calendar.getInstance();
        final Date now = verifyOptions.clock != null ? verifyOptions.clock : cal.getTime();
        final int clockSkew = verifyOptions.clockSkew != null ? verifyOptions.clockSkew : DEFAULT_CLOCK_SKEW;

        if (decoded.getExpiresAt() == null) {
            throw new JWTVerificationException("Expiration Time (exp) claim must be a number present in the ID token");
        }

        cal.setTime(decoded.getExpiresAt());
        cal.add(Calendar.SECOND, clockSkew);
        Date expDate = cal.getTime();

        if (now.after(expDate)) {
            throw new JWTVerificationException(String.format("Expiration Time (exp) claim error in the ID token; current time (%d) is after expiration time (%d)", now.getTime() / 1000, expDate.getTime() / 1000));
        }

        if (decoded.getIssuedAt() == null) {
            throw new JWTVerificationException("Issued At (iat) claim must be a number present in the ID token");
        }

        cal.setTime(decoded.getIssuedAt());
        cal.add(Calendar.SECOND, -1 * clockSkew);

        if (verifyOptions.nonce != null) {
            String nonceClaim = decoded.getClaim(PublicClaims.NONCE).asString();
            if (isEmpty(nonceClaim)) {
                throw new JWTVerificationException("Nonce (nonce) claim must be a string present in the ID token");
            }
            if (!verifyOptions.nonce.equals(nonceClaim)) {
                throw new JWTVerificationException(String.format("Nonce (nonce) claim mismatch in the ID token; expected \"%s\", found \"%s\"", verifyOptions.nonce, nonceClaim));
            }
        }

        if (audience.size() > 1) {
            String azpClaim = decoded.getClaim(PublicClaims.AZP).asString();
            if (isEmpty(azpClaim)) {
                throw new JWTVerificationException("Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values");
            }
            if (!verifyOptions.audience.equals(azpClaim)) {
                throw new JWTVerificationException(String.format("Authorized Party (azp) claim mismatch in the ID token; expected \"%s\", found \"%s\"", verifyOptions.audience, azpClaim));
            }
        }

        if (verifyOptions.maxAge != null) {
            Date authTime = decoded.getClaim(PublicClaims.AUTH_TIME).asDate();
            if (authTime == null) {
                throw new JWTVerificationException("Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified");
            }

            cal.setTime(authTime);
            cal.add(Calendar.SECOND, verifyOptions.maxAge);
            cal.add(Calendar.SECOND, clockSkew);
            Date authTimeDate = cal.getTime();

            if (now.after(authTimeDate)) {
                throw new JWTVerificationException(String.format("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (%d) is after last auth at (%d)", now.getTime() / 1000, authTimeDate.getTime() / 1000));
            }
        }
    }

    private boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    private static class Options {
        private final String issuer;
        private final String audience;
        private final SignatureVerifier verifier;

        private String nonce;
        private Integer maxAge;
        private Integer clockSkew;
        private Date clock;

        Options(String issuer, String audience, SignatureVerifier verifier) {
            Validate.notNull(issuer);
            Validate.notNull(audience);
            Validate.notNull(verifier);
            this.issuer = issuer;
            this.audience = audience;
            this.verifier = verifier;
        }

        void setNonce(String nonce) {
            this.nonce = nonce;
        }

        void setMaxAge(Integer maxAge) {
            this.maxAge = maxAge;
        }

        void setClockSkew(Integer clockSkew) {
            this.clockSkew = clockSkew;
        }

        void setClock(Date now) {
            this.clock = now;
        }
    }
}
