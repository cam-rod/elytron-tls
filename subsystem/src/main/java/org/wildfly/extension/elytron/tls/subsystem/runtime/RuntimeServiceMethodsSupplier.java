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

package org.wildfly.extension.elytron.tls.subsystem.runtime;

import java.util.concurrent.ConcurrentHashMap;

import org.jboss.msc.service.ServiceName;

/**
 * Provides the methods of a {@link org.jboss.msc.Service} or multiple at runtime. 
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class RuntimeServiceMethodsSupplier implements RuntimeServiceSupplier {
    
    protected ConcurrentHashMap<ServiceName,
        ConcurrentHashMap<Class<? extends RuntimeServiceMethods>, RuntimeServiceMethods>> runtimeMethods = new ConcurrentHashMap<>();

    @Override
    public void addService(ServiceName serviceName) {
        runtimeMethods.putIfAbsent(serviceName, new ConcurrentHashMap<>());
    }

    @Override
    public <T extends RuntimeServiceObject> String add(ServiceName serviceName, T object) {
        
        RuntimeServiceMethods methodsObject = (RuntimeServiceMethods) object;
        
        ConcurrentHashMap<Class<? extends RuntimeServiceMethods>,
                RuntimeServiceMethods> service = runtimeMethods.getOrDefault(serviceName, null);
        if (service != null) {
            RuntimeServiceMethods result = runtimeMethods.get(serviceName).put(methodsObject.getMethodsClass(), methodsObject);
            return result != null ? result.getRuntimeObjectDetails() : null;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public <T extends RuntimeServiceMethods> T get(ServiceName serviceName,
            Class<T> methodsClass) {

        ConcurrentHashMap<Class<? extends RuntimeServiceMethods>,
                RuntimeServiceMethods> service = runtimeMethods.getOrDefault(serviceName, null);
        if (service != null) {
            T methods = (T) service.getOrDefault(methodsClass, null);
            return methods;
        }
        return null;
    }

    
}
