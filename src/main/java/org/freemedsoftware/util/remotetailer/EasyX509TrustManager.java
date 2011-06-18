/*
 * ====================================================================
 *
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.freemedsoftware.util.remotetailer;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * EasyX509TrustManager is used by
 * {@link com.poss.auto.http.EasySSLProtocolSocketFactory}
 * to provide SSL functionality to applications
 * using self-signed certificates.
 * 
 */
public class EasyX509TrustManager implements
     X509TrustManager {

     private X509TrustManager standardTrustManager = null;

     public EasyX509TrustManager(KeyStore keystore)
          throws NoSuchAlgorithmException, KeyStoreException {

          super();

          TrustManagerFactory factory = TrustManagerFactory
               .getInstance("SunX509");
          factory.init(keystore);

          TrustManager[] trustmanagers = factory
               .getTrustManagers();

          if (trustmanagers.length == 0) {
               throw new NoSuchAlgorithmException(
                    "SunX509 trust manager not supported");
          }

          this.standardTrustManager = (X509TrustManager) trustmanagers[0];
     }

     public void checkClientTrusted(
          X509Certificate[] certificates,
          String string) throws CertificateException {

          this.standardTrustManager.checkClientTrusted(
               certificates,
               string);
     }

     public void checkServerTrusted(
          X509Certificate[] certificates,
          String string) throws CertificateException {

          if ((certificates != null)
               && (certificates.length == 1)) {
               X509Certificate certificate = certificates[0];

               try {
                    certificate.checkValidity();
               } catch (CertificateException e) {
                    e.printStackTrace();
               }
          } else {
               this.standardTrustManager.checkServerTrusted(
                    certificates,
                    string);
          }
     }

     public X509Certificate[] getAcceptedIssuers() {
          return this.standardTrustManager
               .getAcceptedIssuers();
     }
}
