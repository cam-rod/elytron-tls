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

import static org.wildfly.extension.elytron.tls.subsystem.Constants.KEY_STORE;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.KEY_STORES;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.security.CredentialReference;

class KeyStoreParser {

    final PersistentResourceXMLDescription keyStoreParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(KEY_STORE))
            .setXmlWrapperElement(KEY_STORES)
            .addAttribute(KeyStoreDefinition.TYPE)
            .addAttribute(KeyStoreDefinition.PROVIDER_NAME)
            .addAttribute(KeyStoreDefinition.PROVIDERS)
            .addAttribute(KeyStoreDefinition.CREDENTIAL_REFERENCE)
            .addAttribute(KeyStoreDefinition.ALIAS_FILTER)
            .addAttribute(KeyStoreDefinition.REQUIRED)
            .addAttribute(FileAttributeDefinitions.PATH)
            .addAttribute(FileAttributeDefinitions.RELATIVE_TO)
            .addAttribute(CredentialReference.getAttributeDefinition())
            .build();
}
