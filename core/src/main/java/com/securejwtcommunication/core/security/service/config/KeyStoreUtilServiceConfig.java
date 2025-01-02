package com.securejwtcommunication.core.security.service.config;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@ObjectClassDefinition(
        name = "KeyStore Util Service Configuration",
        description = "KeyStore Util Service Configuration"
)
public @interface KeyStoreUtilServiceConfig {
    @AttributeDefinition(
            name = "senderKeyStoreAliasName",
            description = "Sender KeyStore Alias Name"
    )
    String senderKeyStoreAliasName() default "dbteam";

    @AttributeDefinition(
            name = "senderKeyStorePassword",
            description = "Sender KeyStore Password"
    )
    String senderKeyStorePassword() default "dbteam";

    @AttributeDefinition(
            name = "senderTrustStoreAliasNameInAEM",
            description = "Sender TrustStore Alias Name In AEM"
    )
    String senderTrustStoreAliasNameInAEM() default "certalias___1731780585614";

    @AttributeDefinition(
            name = "receiverKeyStoreAliasName",
            description = "Receiver KeyStore Alias Name"
    )
    String receiverKeyStoreAliasName() default "naopteam";

    @AttributeDefinition(
            name = "receiverKeyStorePassword",
            description = "Receiver KeyStore Password"
    )
    String receiverKeyStorePassword() default "naopteam";

    @AttributeDefinition(
            name = "receiverTrustStoreAliasNameInAEM",
            description = "Receiver TrustStore Alias Name In AEM"
    )
    String receiverTrustStoreAliasNameInAEM() default "certalias___1731780554839";

}
