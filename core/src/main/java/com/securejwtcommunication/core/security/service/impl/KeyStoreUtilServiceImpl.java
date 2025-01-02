package com.securejwtcommunication.core.security.service.impl;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Objects;

import com.adobe.granite.keystore.KeyStoreService;
import com.securejwtcommunication.core.security.service.KeyStoreUtilService;
import com.securejwtcommunication.core.security.service.ResourceResolverService;
import com.securejwtcommunication.core.security.service.config.KeyStoreUtilServiceConfig;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.resource.ResourceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ServiceScope;
import org.osgi.service.metatype.annotations.Designate;

@Component(service = KeyStoreUtilService.class, scope = ServiceScope.SINGLETON, immediate = true)
@Designate(ocd = KeyStoreUtilServiceConfig.class)
public class KeyStoreUtilServiceImpl implements KeyStoreUtilService{
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreUtilServiceImpl.class);

    @Reference
    private KeyStoreService keyStoreService;

    @Reference
    ResourceResolverService resourceResolverService;

    private KeyStoreUtilServiceConfig keyStoreUtilServiceConfig;

    private String receiverKeyStoreAliasName = StringUtils.EMPTY;
    private String receiverKeystorePassword = StringUtils.EMPTY;
    private String receiverTrustStoreAliasNameInAEM = StringUtils.EMPTY;

    private String senderKeyStoreAliasName = StringUtils.EMPTY;
    private String senderKeystorePassword = StringUtils.EMPTY;
    private String senderTrustStoreAliasNameInAEM = StringUtils.EMPTY;

    /**
     * Retrieves a ResourceResolver for the specified service user.
     *
     * <p>This method attempts to obtain a ResourceResolver for the given service user using the
     * ResourceResolverService. It checks whether the keystore exists for the service user.
     * If an exception occurs during the process, it is caught and logged as an error.</p>
     *
     * @param serviceUser the ID of the service user for whom the ResourceResolver is to be obtained
     * @throws Exception if there is an error in fetching the ResourceResolver
     */
    private ResourceResolver getResourceResolverForServiceUser(String serviceUser) {
        LOGGER.debug("getResourceResolverForServiceUser >> Start");
        ResourceResolver resourceResolver = null;
        try {
            resourceResolver = resourceResolverService.getResourceResolver(serviceUser);
            LOGGER.debug("ResourceResolver - Service User ID : {}", resourceResolver.getUserID());
            LOGGER.debug("isKeystoreExists : {}", keyStoreService.keyStoreExists(resourceResolver, serviceUser));
        } catch (Exception exception) {
            LOGGER.error("Error in Fetching Resource Resolver for service user", exception);
        }
        LOGGER.debug("getResourceResolverForServiceUser >> End, ResourceResolver : {}", resourceResolver);
        return resourceResolver;
    }

    /**
     * Fetches the public key from the AEM TrustStore for the specified alias and service user.
     *
     * <p>This method retrieves a ResourceResolver for the given service user and then attempts to
     * fetch the public key from the AEM TrustStore using the provided trust store alias. It logs the
     * start and completion of the process, as well as any errors that occur during the fetching of
     * the public key. If the trust store or the certificate is not found, it returns null.</p>
     *
     * @param trustStoreAlias the alias of the trust store from which the public key is to be fetched
     * @param serviceUser the ID of the service user for whom the ResourceResolver is to be obtained
     * @return the public key if found, or null if not found or an error occurs
     * @throws Exception if there is an error in fetching the ResourceResolver or the public key
     */
    @Override
    public PublicKey fetchPublicKeyFromAEMTrustStore(String trustStoreAlias,String serviceUser) {
        LOGGER.debug("fetchPublicKey>>Start");
        PublicKey publicKey = null;
        try {
            ResourceResolver resourceResolver = getResourceResolverForServiceUser(serviceUser);
            KeyStore trustStore = keyStoreService.getTrustStore(resourceResolver);
            if (trustStore != null) {
                X509Certificate certificate = null;
                try {
                    certificate = (X509Certificate) trustStore.getCertificate(trustStoreAlias);
                } catch (KeyStoreException e) {
                    LOGGER.error("fetchPublicKey >> Error in Fetching Public Key", e);
                }
                publicKey = Objects.nonNull(certificate) ? certificate.getPublicKey() : null;
            }
        } catch (Exception exception) {
            LOGGER.error("fetchPublicKey >> Error occurred!", exception);
        }
        LOGGER.debug("fetchPublicKey >> Complete");
        return publicKey;
    }

    /**
     * Fetches the public key from the KeyStore for the specified alias and service user.
     *
     * <p>This method retrieves a ResourceResolver for the given service user and then attempts to
     * fetch the public key from the KeyStore using the provided keystore alias. It logs the start
     * and completion of the process, as well as any errors that occur during the fetching of the
     * public key. If the KeyStore or the certificate is not found, it returns null. The ResourceResolver
     * is closed if it is live at the end of the process.</p>
     *
     * @param keystoreAlias the alias of the keystore from which the public key is to be fetched
     * @param serviceUser the ID of the service user for whom the ResourceResolver is to be obtained
     * @return the public key if found, or null if not found or an error occurs
     * @throws Exception if there is an error in fetching the ResourceResolver or the public key
     */
    @Override
    public PublicKey fetchPublicKey(String keystoreAlias,String serviceUser) {
        LOGGER.debug("fetchPublicKey >> Start");
        PublicKey publicKey = null;
        ResourceResolver resourceResolver = null;
        try {
            resourceResolver = getResourceResolverForServiceUser(serviceUser);
            KeyStore keyStore = keyStoreService.getKeyStore(resourceResolver);
            if (keyStore != null) {
                X509Certificate certificate = null;
                try {
                    certificate = (X509Certificate) keyStore.getCertificate(keystoreAlias);
                } catch (KeyStoreException e) {
                    LOGGER.error("fetchPublicKey >> Error in Fetching Public Key", e);
                }
                publicKey = Objects.nonNull(certificate) ? certificate.getPublicKey() : null;
            }
        } catch (Exception exception) {
            LOGGER.error("fetchPublicKey >> Error occurred!", exception);
        } finally {
            if (resourceResolver != null && resourceResolver.isLive()) {
                resourceResolver.close();
            }
        }
        LOGGER.debug("fetchPublicKey >> Complete");
        return publicKey;
    }

    /**
     * Fetches the private key from the KeyStore for the specified alias, password, and service user.
     *
     * <p>This method retrieves a ResourceResolver for the given service user and then attempts to
     * fetch the private key from the KeyStore using the provided keystore alias and password. It logs
     * the start and completion of the process, as well as any errors that occur during the fetching
     * of the private key. If the KeyStore or the private key is not found, it returns null.</p>
     *
     * @param keyStoreAlias the alias of the keystore from which the private key is to be fetched
     * @param keyStorePwd the password of the keystore
     * @param serviceUser the ID of the service user for whom the ResourceResolver is to be obtained
     * @return the private key if found, or null if not found or an error occurs
     * @throws Exception if there is an error in fetching the ResourceResolver or the private key
     */
    @Override
    public PrivateKey fetchPrivateKey(String keyStoreAlias, String keyStorePwd, String serviceUser) {
        LOGGER.debug("fetchPrivateKey>>Start");
        PrivateKey privateKey = null;
        try {
            ResourceResolver resourceResolver = getResourceResolverForServiceUser(serviceUser);
            KeyStore keyStore = keyStoreService.getKeyStore(resourceResolver);
            try {
                privateKey = (PrivateKey) keyStore.getKey(keyStoreAlias, keyStorePwd.toCharArray());
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
                LOGGER.error("fetchPrivateKey >> Error in Fetching Private Key", exception);
            }
        } catch (Exception exception) {
            LOGGER.error("fetchPrivateKey >> Error occurred!", exception);
        }
        LOGGER.debug("fetchPrivateKey>>Complete");
        return privateKey;
    }

    /**
     * Retrieves the sender's key store alias from the configuration.
     *
     * @return the sender's key store alias
     */
    @Override
    public String senderKeyStoreAliasFromConfig() {
        return senderKeyStoreAliasName;
    }

    /**
     * Retrieves the sender's key store password from the configuration.
     *
     * @return the sender's key store password
     */
    @Override
    public String senderKeystorePasswordFromConfig() {
        return senderKeystorePassword;
    }

    /**
     * Retrieves the sender's trust store alias in AEM from the configuration.
     *
     * @return the sender's trust store alias in AEM
     */
    @Override
    public String senderTrustStoreAliasInAEMFromConfig() {
        return senderTrustStoreAliasNameInAEM;
    }

    /**
     * Retrieves the receiver's key store alias from the configuration.
     *
     * @return the receiver's key store alias
     */
    @Override
    public String receiverKeyStoreAliasFromConfig() {
        return receiverKeyStoreAliasName;
    }

    /**
     * Retrieves the receiver's key store password from the configuration.
     *
     * @return the receiver's key store password
     */
    @Override
    public String receiverKeystorePasswordFromConfig() {
        return receiverKeystorePassword;
    }

    /**
     * Retrieves the receiver's trust store alias in AEM from the configuration.
     *
     * @return the receiver's trust store alias in AEM
     */
    @Override
    public String receiverTrustStoreAliasInAEMFromConfig() {
        return receiverTrustStoreAliasNameInAEM;
    }


    /**
     * Activates the KeyStoreUtilService with the provided configuration.
     *
     * <p>This method initializes the KeyStoreUtilService by setting the configuration properties
     * for the receiver and sender key store aliases, passwords, and trust store aliases in AEM.
     * It logs the start and completion of the activation process.</p>
     *
     * @param config the KeyStoreUtilServiceConfig object containing the configuration properties
     */

    @Activate
    protected void activate(KeyStoreUtilServiceConfig config) {
        LOGGER.info("activate >> Start");
        this.keyStoreUtilServiceConfig = config;
        receiverKeyStoreAliasName = keyStoreUtilServiceConfig.receiverKeyStoreAliasName();
        receiverKeystorePassword = keyStoreUtilServiceConfig.receiverKeyStorePassword();
        receiverTrustStoreAliasNameInAEM = keyStoreUtilServiceConfig.receiverTrustStoreAliasNameInAEM();

        senderKeyStoreAliasName = keyStoreUtilServiceConfig.senderKeyStoreAliasName();
        senderKeystorePassword = keyStoreUtilServiceConfig.senderKeyStorePassword();
        senderTrustStoreAliasNameInAEM = keyStoreUtilServiceConfig.senderTrustStoreAliasNameInAEM();
        LOGGER.info("activate >> Complete");
    }

    /**
     * Deactivates the service.
     */
    @Deactivate
    protected void deactivate() {
        LOGGER.info("deactivate >> Start");
        LOGGER.info("deactivate >> Complete");
    }
}
