/*
 * Copyright 2022 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron.tls;

import java.security.KeyStore;
import java.security.Provider;
import java.util.function.Consumer;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.msc.service.ServiceBuilder;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.x500.cert.acme.AcmeAccount;
import org.wildfly.security.x500.cert.acme.CertificateAuthority;

/**
 * The capabilities provided by and required by this subsystem.
 *
 * The capabilities are same as the ones provided by the Elytron subsystem
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
class Capabilities {

    // This has to be at this position, and must not be a lambda, to avoid an init circularity problem on IBM
    @SuppressWarnings("Convert2Lambda")
    static final Consumer<ServiceBuilder> COMMON_REQUIREMENTS = new Consumer<ServiceBuilder>() {
        // unchecked because ServiceBuilder is a raw type
        @SuppressWarnings("unchecked")
        public void accept(final ServiceBuilder serviceBuilder) {
            ElytronTlsSubsystemDefinition.commonRequirements(serviceBuilder);
        }
    };

    private static final String WILDFLY_SECURITY_CAPABILITY_BASE = "org.wildfly.security.";

    static final String ELYTRON_TLS_CAPABILITY_NAME = "org.wildfly.extras.elytron-tls";
    
    static final RuntimeCapability<Consumer<ServiceBuilder>> ELYTRON_TLS_RUNTIME_CAPABILITY = RuntimeCapability.Builder
            .of(ELYTRON_TLS_CAPABILITY_NAME, COMMON_REQUIREMENTS)
            .build();

    static final String CERTIFICATE_AUTHORITY_ACCOUNT_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "certificate-authority-account";

    static final RuntimeCapability<Void> CERTIFICATE_AUTHORITY_ACCOUNT_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(CERTIFICATE_AUTHORITY_ACCOUNT_CAPABILITY, true, AcmeAccount.class)
            .build();

    static final String CERTIFICATE_AUTHORITY_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "certificate-authority";

    static final RuntimeCapability<Void> CERTIFICATE_AUTHORITY_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(CERTIFICATE_AUTHORITY_CAPABILITY, true, CertificateAuthority.class)
            .build();

    static final String CREDENTIAL_STORE_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "credential-store";

    /*
     * A variant of the credential-store capability which also provides access to the underlying
     * {@code CredentialStore} as a runtime API from a {@code ExceptionFunction<OperationContext, CredentialStore, OperationFailedException>}.
     */
    static final String CREDENTIAL_STORE_API_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "credential-store-api";

    static final RuntimeCapability<Void> CREDENTIAL_STORE_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(CREDENTIAL_STORE_CAPABILITY, true, CredentialStore.class)
            .build();

    static final String KEY_MANAGER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "key-manager";

    static final RuntimeCapability<Void> KEY_MANAGER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(KEY_MANAGER_CAPABILITY, true, KeyManager.class)
            .build();

    static final String KEY_STORE_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "key-store";

    static final RuntimeCapability<Void> KEY_STORE_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(KEY_STORE_CAPABILITY, true, KeyStore.class)
            .build();

    static final String PROVIDERS_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "providers";

    /*
     * A variant of the credential-store capability which also provides access to the underlying
     * {@code CredentialStore} as a runtime API from a {@code ExceptionFunction<OperationContext, Provider[], OperationFailedException>}.
     */
    static final String PROVIDERS_API_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "providers-api";

    static final RuntimeCapability<Void> PROVIDERS_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(PROVIDERS_CAPABILITY, true, Provider[].class)
            .build();

    static final String SSL_CONTEXT_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "ssl-context";

    static final RuntimeCapability<Void> SSL_CONTEXT_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(SSL_CONTEXT_CAPABILITY, true, SSLContext.class)
            .build();

    static final String TRUST_MANAGER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "trust-manager";

    static final RuntimeCapability<Void> TRUST_MANAGER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(TRUST_MANAGER_CAPABILITY, true, TrustManager.class)
            .build();


    static final String EXPRESSION_RESOLVER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "expression-resolver";

}
