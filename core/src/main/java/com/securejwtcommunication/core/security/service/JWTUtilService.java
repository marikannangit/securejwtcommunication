package com.securejwtcommunication.core.security.service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface JWTUtilService {

    /**
     * Decrypts String with Jose Algorithm using sender's public key and receiver's private key
     * @param rsaPublicKey
     * @param rsaPrivateKey
     * @param response
     * @return
     * @throws Exception
     */
    String decryption(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey, String response) throws Exception;

    /**
     * Encrypts String using Jose Algorithm using sender's private key and receiver's public key and other relevant information
     * @param rsaPublicKey
     * @param rsaPrivateKey
     * @param payload
     * @param jweThumbprint
     * @param jwsThumbprint
     * @param clientId
     * @return
     * @throws Exception
     */
     String encryption(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey,String payload, String jweThumbprint, String jwsThumbprint, String clientId) throws  Exception;
}
