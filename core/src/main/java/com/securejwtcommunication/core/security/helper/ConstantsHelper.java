package com.securejwtcommunication.core.security.helper;

/**
 * A utility class to hold constants
 */
public final class ConstantsHelper {

    // Prevent instantiation
    private ConstantsHelper() {}

    /**
     * The issuer of the JWT.
     */
    public static final String ISSUER = "https://jwtissuer.com";

    /**
     * The audience for which the JWT is intended.
     */
    public static final String AUDIENCE = "https://api.jwt.com";

    /**
     * The subject of the JWT.
     */
    public static final String SUBJECT = "SubjectJWT123";

    /**
     * The service user for the authentication receiver.
     */
    public static final String RECEIVER_SERVICE_USER = "authentication-service";

    /**
     * The service user for the sender.
     */
    public static final String SENDER_SERVICE_USER = "fd-service";
}
