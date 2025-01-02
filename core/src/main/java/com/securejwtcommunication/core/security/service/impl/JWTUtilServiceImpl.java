package com.securejwtcommunication.core.security.service.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.securejwtcommunication.core.security.helper.ConstantsHelper;
import com.securejwtcommunication.core.security.service.JWTUtilService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

@Component(service = JWTUtilService.class, immediate = true, name = "JWT Util Service Implementation", configurationPolicy = ConfigurationPolicy.OPTIONAL)
public class JWTUtilServiceImpl implements JWTUtilService {
    private static final Logger LOGGER = LoggerFactory.getLogger(JWTUtilServiceImpl.class);

    /**
     * Decrypt and validate a JWT response.
     *
     * @param rsaPublicKey  Public RSA key to verify the JWT signature.
     * @param rsaPrivateKey Private RSA key to decrypt the JWT.
     * @param response      JWT response as a string.
     * @return Decrypted JWT payload as a string.
     * @throws Exception If decryption or validation fails.
     */
    @Override
    public String decryption(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey, String response) throws Exception {
        LOGGER.debug("decryption >> Start");
        try {
            // Parse and verify the signed JWT
            SignedJWT signedJWT = SignedJWT.parse(response);

            JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
            if (!JWSAlgorithm.RS256.equals(algorithm) && !JWSAlgorithm.PS256.equals(algorithm)) {
                throw new IllegalArgumentException("Unsupported or missing JWT signing algorithm: " + algorithm);
            }

            JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);
            if (!signedJWT.verify(verifier)) {
                throw new SecurityException("JWT signature verification failed!");
            }

            // Parse the payload as a JWE object
            JWEObject jweObject = JWEObject.parse(signedJWT.getPayload().toString());
            jweObject.decrypt(new RSADecrypter(rsaPrivateKey));

            // Extract and validate claims
            JWTClaimsSet claimsSet = JWTClaimsSet.parse(jweObject.getPayload().toString());
            validateTokenClaims(claimsSet);

            LOGGER.debug("decryption >> Decryption and validation successful");
            return jweObject.getPayload().toString();

        } catch (Exception e) {
            LOGGER.error("decryption >> Error occurred", e);
            throw new Exception("Failed to decrypt and validate JWT response", e);
        }
    }

    /**
     * Encrypt and sign a request payload using JWT.
     *
     * @param rsaPublicKey  Public RSA key to encrypt the payload.
     * @param rsaPrivateKey Private RSA key to sign the JWT.
     * @param payload       The payload to encrypt and sign.
     * @param receiverThumbprint JWE thumbprint for header metadata.
     * @param senderThumbprint JWS thumbprint for header metadata.
     * @param clientId      The client ID for custom claims.
     * @return The serialized encrypted and signed JWT.
     * @throws Exception If encryption or signing fails.
     */
    @Override
    public String encryption(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey, String payload, String receiverThumbprint, String senderThumbprint, String clientId) throws Exception {
        LOGGER.debug("encryption >> Start");
        try {
            // Create JWT claims
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(ConstantsHelper.ISSUER)
                    .audience(ConstantsHelper.AUDIENCE)
                    .subject(ConstantsHelper.SUBJECT)
                    .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour expiry
                    .notBeforeTime(new Date())
                    .issueTime(new Date())
                    .jwtID("jwt-" + System.currentTimeMillis())
                    .claim("payload", payload)
                    .claim("clientid", clientId)
                    .build();

            // Encrypt claims into a JWE object
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                            .x509CertSHA256Thumbprint(Base64URL.from(receiverThumbprint))
                            .customParam("clientid", clientId)
                            .build(),
                    new Payload(claimsSet.toString())
            );
            jweObject.encrypt(new RSAEncrypter(rsaPublicKey));

            // Sign the JWE as a nested JWT
            JWSObject jwsObject = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.PS256)
                            .contentType("JWT") // Indicates nested JWT
                            .x509CertSHA256Thumbprint(Base64URL.from(senderThumbprint))
                            .customParam("clientid", clientId)
                            .build(),
                    new Payload(jweObject.serialize())
            );
            jwsObject.sign(new RSASSASigner(rsaPrivateKey));

            LOGGER.debug("encryption >> Encryption and signing successful");
            return jwsObject.serialize();

        } catch (Exception e) {
            LOGGER.error("encryption >> Error occurred", e);
            throw new Exception("Failed to encrypt and sign request", e);
        }
    }

    /**
     * Validate JWT claims.
     *
     * @param claimsSet Parsed JWT claims.
     * @throws Exception If validation fails.
     */
    private void validateTokenClaims(JWTClaimsSet claimsSet) throws Exception {
        LOGGER.debug("validateTokenClaims >> Token claims validation start");
        Date now = new Date();

        if (claimsSet.getExpirationTime() == null || now.after(claimsSet.getExpirationTime())) {
            throw new Exception("Token is expired");
        }

        if (claimsSet.getNotBeforeTime() != null && now.before(claimsSet.getNotBeforeTime())) {
            throw new Exception("Token is not valid yet");
        }

        if (claimsSet.getIssueTime() == null || now.before(claimsSet.getIssueTime())) {
            throw new Exception("Invalid issue time");
        }

        if (claimsSet.getAudience() == null || !claimsSet.getAudience().contains(ConstantsHelper.AUDIENCE)) {
            throw new Exception("Invalid audience");
        }

        if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals(ConstantsHelper.ISSUER)) {
            throw new Exception("Invalid issuer");
        }

        if (claimsSet.getSubject() == null || claimsSet.getSubject().isEmpty()) {
            throw new Exception("Invalid subject");
        }

        LOGGER.debug("validateTokenClaims >> Token claims validated successfully");
    }

    @Activate
    protected void activate() {
        LOGGER.info("activate >> Start");
        LOGGER.info("activate >> Complete");
    }

    @Deactivate
    protected void deactivate() {
        LOGGER.info("activate >> Start");
        LOGGER.info("activate >> Complete");
    }
}
