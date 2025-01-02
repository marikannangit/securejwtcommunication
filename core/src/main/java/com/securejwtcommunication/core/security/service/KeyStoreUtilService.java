package com.securejwtcommunication.core.security.service;

import java.security.*;

public interface KeyStoreUtilService {

    /**
     * Fetches the public key from the trust store using the provided alias.
     *
     * @param trustStoreAlias the alias of the trust store
     * @return the public key
     */
    PublicKey fetchPublicKeyFromAEMTrustStore(String trustStoreAlias,String serviceUser);

    /**
     * Fetches the public key from the trust store using the provided alias.
     *
     * @param keystoreAlias the alias of the trust store
     * @return the public key
     */
    PublicKey fetchPublicKey(String keystoreAlias,String serviceUser);

    /**
     * Fetches the private key from the key store using the provided alias and password.
     *
     * @param keyStoreAlias the alias of the key store
     * @param keyStorePwd the password of the key store
     * @return the private key
     */
    PrivateKey fetchPrivateKey(String keyStoreAlias, String keyStorePwd,String serviceUser);

    /**
     * Retrieves the sender key store alias from the configuration.
     *
     * @return the sender key store alias
     */
    String senderKeyStoreAliasFromConfig();

    /**
     * Retrieves the sender key store password from the configuration.
     *
     * @return the sender key store password
     */
    String senderKeystorePasswordFromConfig();

    /**
     * Retrieves the sender trust store alias in AEM from the configuration.
     *
     * @return the sender trust store alias
     */
    String senderTrustStoreAliasInAEMFromConfig();

    /**
     * Retrieves the receiver key store alias from the configuration.
     *
     * @return the receiver key store alias
     */
    String receiverKeyStoreAliasFromConfig();

    /**
     * Retrieves the receiver key store password from the configuration.
     *
     * @return the receiver key store password
     */
    String receiverKeystorePasswordFromConfig();

    /**
     * Retrieves the receiver trust store alias in AEM from the configuration.
     *
     * @return the receiver trust store alias
     */
    String receiverTrustStoreAliasInAEMFromConfig();

}
