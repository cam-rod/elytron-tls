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

package org.wildfly.extension.elytron.tls.subsystem;

import static org.wildfly.extension.elytron.tls.subsystem.Constants.KEY_MANAGER_OBJECT;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.KEY_MANAGERS;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.TRUST_MANAGER_OBJECT;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.TRUST_MANAGERS;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.security.CredentialReference;

class ManagerParsers {

    final PersistentResourceXMLDescription keyManagerParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(KEY_MANAGER_OBJECT))
            .setXmlWrapperElement(KEY_MANAGERS)
            .addAttribute(SSLContextDefinitions.ALGORITHM)
            .addAttribute(SSLContextDefinitions.KEY_STORE)
        //     .addAttribute(SSLContextDefinitions.KEY_STORE_OBJECT)
            .addAttribute(SSLContextDefinitions.ALIAS_FILTER)
            .addAttribute(SSLContextDefinitions.PROVIDER_NAME)
            .addAttribute(SSLContextDefinitions.PROVIDERS)
            .addAttribute(SSLContextDefinitions.GENERATE_SELF_SIGNED_CERTIFICATE_HOST) // new
            .addAttribute(CredentialReference.getAttributeDefinition())
            .build();

    final PersistentResourceXMLDescription trustManagerParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(TRUST_MANAGER_OBJECT))
            .setXmlWrapperElement(TRUST_MANAGERS)
            .addAttribute(SSLContextDefinitions.ALGORITHM)
            .addAttribute(SSLContextDefinitions.KEY_STORE)
        //     .addAttribute(SSLContextDefinitions.KEY_STORE_OBJECT)
            .addAttribute(SSLContextDefinitions.ALIAS_FILTER)
            .addAttribute(SSLContextDefinitions.PROVIDERS)
            .addAttribute(SSLContextDefinitions.PROVIDER_NAME)
            .addAttribute(SSLContextDefinitions.CERTIFICATE_REVOCATION_LIST)
            .addAttribute(SSLContextDefinitions.OCSP)
            .addAttribute(SSLContextDefinitions.ONLY_LEAF_CERT)
            .addAttribute(SSLContextDefinitions.SOFT_FAIL)
            .addAttribute(SSLContextDefinitions.MAXIMUM_CERT_PATH)
            .addAttribute(SSLContextDefinitions.CERTIFICATE_REVOCATION_LISTS)
            .build();
}
