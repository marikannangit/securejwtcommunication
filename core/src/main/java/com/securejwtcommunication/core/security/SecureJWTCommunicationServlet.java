package com.securejwtcommunication.core.security;


import com.nimbusds.jose.util.Base64URL;
import com.securejwtcommunication.core.security.helper.ConstantsHelper;
import com.securejwtcommunication.core.security.service.JWTUtilService;
import com.securejwtcommunication.core.security.service.KeyStoreUtilService;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component(service = Servlet.class,
        property = {
                Constants.SERVICE_DESCRIPTION + "=Secure JWT Communication Servlet",
                "sling.servlet.paths=/security/encryptRequestWithJWT",
                "sling.servlet.methods={GET,POST}"
        })
public class SecureJWTCommunicationServlet extends SlingAllMethodsServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LoggerFactory.getLogger(SecureJWTCommunicationServlet.class);

    @Reference
    KeyStoreUtilService keyStoreUtilService;

    @Reference
    JWTUtilService jwtUtilService;

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response) throws IOException {
        LOGGER.info("GET >> Start");
        try {
            String payload = request.getParameter("payload");
            String clientId = request.getParameter("clientId");

            String senderKeyStoreAliasName = keyStoreUtilService.senderKeyStoreAliasFromConfig();
            String senderKeystorePassword = keyStoreUtilService.senderKeystorePasswordFromConfig();
            String senderTrustStoreAliasNameInAEM = keyStoreUtilService.senderTrustStoreAliasInAEMFromConfig();

            String receiverKeyStoreAliasName = keyStoreUtilService.receiverKeyStoreAliasFromConfig();
            String receiverKeystorePassword = keyStoreUtilService.receiverKeystorePasswordFromConfig();
            String receiverTrustStoreAliasNameInAEM = keyStoreUtilService.receiverTrustStoreAliasInAEMFromConfig();

            // Retrieve keys
            RSAPrivateKey receiverPrivateKey  = (RSAPrivateKey) keyStoreUtilService.fetchPrivateKey(receiverKeyStoreAliasName,receiverKeystorePassword, ConstantsHelper.RECEIVER_SERVICE_USER);
            RSAPublicKey receiverPublicKey = (RSAPublicKey) keyStoreUtilService.fetchPublicKeyFromAEMTrustStore(receiverTrustStoreAliasNameInAEM,ConstantsHelper.RECEIVER_SERVICE_USER);
            LOGGER.info("GET >> receiverPrivateKey:{}, receiverPublicKey:{}",receiverPrivateKey,receiverPublicKey);
            RSAPrivateKey senderPrivateKey = (RSAPrivateKey) keyStoreUtilService.fetchPrivateKey(senderKeyStoreAliasName,senderKeystorePassword,ConstantsHelper.SENDER_SERVICE_USER);
            RSAPublicKey senderPublicKey = (RSAPublicKey) keyStoreUtilService.fetchPublicKeyFromAEMTrustStore(senderTrustStoreAliasNameInAEM,ConstantsHelper.SENDER_SERVICE_USER);
            LOGGER.info("GET >> senderPrivateKey:{}, senderPublicKey:{}",senderPrivateKey,senderPublicKey);

            // Thumbprints
            String receiverThumbprint = computeThumbprint(receiverPublicKey); // Receiver's public key
            String senderThumbprint = computeThumbprint(senderPublicKey);   // Sender's public key
            LOGGER.info("GET >> Receiver's Thumbprint:{}, Sender's Thumbprint:{}",receiverThumbprint,senderThumbprint);

            // Call encryptRequestWithJWT
            String encryptedJWT = jwtUtilService.encryption(receiverPublicKey, senderPrivateKey, payload, receiverThumbprint, senderThumbprint, clientId);

            // Send response
            response.setContentType("application/json");
            response.getWriter().write("{\"encryptedJWT\":\"" + encryptedJWT + "\"}");

        } catch (Exception e) {
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"" + e.getMessage() + "\"}");
        }
        LOGGER.info("GET >> Complete");
    }

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) throws IOException {
        LOGGER.info("POST >> Start");
        String encryptedJWTRequest = request.getParameter("encryptedJWT");

        String senderKeyStoreAliasName = keyStoreUtilService.senderKeyStoreAliasFromConfig();
        String senderKeystorePassword = keyStoreUtilService.senderKeystorePasswordFromConfig();
        String senderTrustStoreAliasNameInAEM = keyStoreUtilService.senderTrustStoreAliasInAEMFromConfig();

        String receiverKeyStoreAliasName = keyStoreUtilService.receiverKeyStoreAliasFromConfig();
        String receiverKeystorePassword = keyStoreUtilService.receiverKeystorePasswordFromConfig();
        String receiverTrustStoreAliasNameInAEM = keyStoreUtilService.receiverTrustStoreAliasInAEMFromConfig();

        // Retrieve keys
        RSAPrivateKey receiverPrivateKey  = (RSAPrivateKey) keyStoreUtilService.fetchPrivateKey(receiverKeyStoreAliasName,receiverKeystorePassword,ConstantsHelper.RECEIVER_SERVICE_USER);
        RSAPublicKey receiverPublicKey = (RSAPublicKey) keyStoreUtilService.fetchPublicKeyFromAEMTrustStore(receiverTrustStoreAliasNameInAEM,ConstantsHelper.RECEIVER_SERVICE_USER);
        LOGGER.info("GET >> receiverPrivateKey:{}, receiverPublicKey:{}",receiverPrivateKey,receiverPublicKey);
        RSAPrivateKey senderPrivateKey = (RSAPrivateKey) keyStoreUtilService.fetchPrivateKey(senderKeyStoreAliasName,senderKeystorePassword,ConstantsHelper.SENDER_SERVICE_USER);
        RSAPublicKey senderPublicKey = (RSAPublicKey) keyStoreUtilService.fetchPublicKeyFromAEMTrustStore(senderTrustStoreAliasNameInAEM,ConstantsHelper.SENDER_SERVICE_USER);
        LOGGER.info("GET >> senderPrivateKey:{}, senderPublicKey:{}",senderPrivateKey,senderPublicKey);

        try {
            String decryptJWT = jwtUtilService.decryption(senderPublicKey,receiverPrivateKey, encryptedJWTRequest);
            response.getWriter().write("{\"decryptJWT\":\"" + decryptJWT + "\"}");
        } catch (Exception e) {
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"" + e.getMessage() + "\"}");
        }
        LOGGER.info("POST >> Complete");
    }

    private String computeThumbprint(PublicKey publicKey) throws Exception {
        byte[] encodedKey = publicKey.getEncoded();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(encodedKey);
        return Base64URL.encode(hash).toString();
    }

    @Activate
    protected void activate() throws IOException {
        LOGGER.info("activate >> Start");
        LOGGER.info("activate >> Complete");
    }

    @Deactivate
    protected void deactivate() throws IOException {
        LOGGER.info("activate >> Start");
        LOGGER.info("activate >> Complete");
    }

}

