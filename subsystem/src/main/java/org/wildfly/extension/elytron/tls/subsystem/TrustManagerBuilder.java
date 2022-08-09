package org.wildfly.extension.elytron.tls.subsystem;

import java.security.KeyStore;

import javax.net.ssl.TrustManager;

import org.wildfly.common.function.ExceptionSupplier;

public class TrustManagerBuilder {
    private ExceptionSupplier<KeyStore, Exception> keyStoreSupplier;
    private String keyStoreReferenceName;
    private String aliasFilter;
    private String algorithm;
    private int maximumCertPath;
    private boolean onlyLeafCert;
    private boolean softFail;
    private String providerName;

    private String ocspResponder;
    private boolean preferCrls;
    private String responderCertificate;
    private ExceptionSupplier<KeyStore, Exception> responderKeyStore;


    public TrustManagerBuilder() {

    }

    public TrustManager build() {


        return null;
    }

}
