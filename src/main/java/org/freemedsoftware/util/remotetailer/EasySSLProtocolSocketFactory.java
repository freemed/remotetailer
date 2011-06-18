/*
 * $HeadURL$
 * $Revision: 2005 $
 * $Date: 2010-04-20 15:16:06 -0400 (Tue, 20 Apr 2010) $
 * 
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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.HttpClientError;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.*;

/**
 * EasySSLProtocolSocketFactory is a secure
 * socket factory that makes it possible
 * to provide SSL encryption to applications
 * using self-signed certificates.

 * 
 * WARNING!!! Accepting any old self-signed certiicate
 * is NOT a good idea,
 * unless all you want is secure transmission of
 * data to/from a known server.
 *
 */
public class EasySSLProtocolSocketFactory implements
     SecureProtocolSocketFactory {

     private SSLContext sslcontext = null;

     private static SSLContext createEasySSLContext() {
          try {
               SSLContext context = SSLContext
                    .getInstance("SSL");
               context
                    .init(
                         null,
                         new TrustManager[] { new EasyX509TrustManager(
                              null) },
                         null);

               return context;
          } catch (Exception e) {
               throw new HttpClientError(e.toString());
          }
     }

     private SSLContext getSSLContext() {
          if (this.sslcontext == null) {
               this.sslcontext = createEasySSLContext();
          }

          return this.sslcontext;
     }

     public Socket createSocket(
          String host,
          int port,
          InetAddress clientHost,
          int clientPort) throws IOException,
          UnknownHostException {

          return getSSLContext().getSocketFactory()
               .createSocket(
                    host,
                    port,
                    clientHost,
                    clientPort);
     }

     /**
      * Attempts to get a new socket connection to
      * the given host within the given time limit.
      * 

      * To circumvent the limitations of older JREs
      * that do not support connect timeout a
      * controller thread is executed. The controller
      * thread attempts to create a new socket
      * within the given limit of time. If socket
      * constructor does not return until the
      * timeout expires, the controller terminates
      * and throws an {@link ConnectTimeoutException}
      * 
      * 
      * @param host the host name/IP
      * @param port the port on the host
      * @param clientHost the local host name/IP to
      * bind the socket to
      * @param clientPort the port on the local machine
      * @param params {@link HttpConnectionParams
      * Http connection parameters}
      * 
      * @return Socket a new socket
      * 
      * @throws IOException if an I/O error occurs
      * while creating the socket
      * @throws UnknownHostException if the IP address
      * of the host cannot be
      * determined
      */
     public Socket createSocket(
          final String host,
          final int port,
          final InetAddress localAddress,
          final int localPort,
          final HttpConnectionParams params)
          throws IOException, UnknownHostException,
          ConnectTimeoutException {
          if (params == null) {
               throw new IllegalArgumentException(
                    "Parameters may not be null");

          }
          int timeout = params.getConnectionTimeout();
          if (timeout == 0) {
               return createSocket(
                    host,
                    port,
                    localAddress,
                    localPort);
          } else {
               // To be eventually deprecated
               // when migrated to Java 1.4 or above
               return ControllerThreadSocketFactory
                    .createSocket(
                         this,
                         host,
                         port,
                         localAddress,
                         localPort,
                         timeout);
          }
     }

     public Socket createSocket(String host, int port)
          throws IOException, UnknownHostException {
          return getSSLContext().getSocketFactory()
               .createSocket(host, port);
     }

     public Socket createSocket(
          Socket socket,
          String host,
          int port,
          boolean autoClose) throws IOException,
          UnknownHostException {
          return getSSLContext().getSocketFactory()
               .createSocket(socket, host, port, autoClose);
     }

     public boolean equals(Object obj) {
          return ((obj != null) && obj.getClass().equals(
               EasySSLProtocolSocketFactory.class));
     }

     public int hashCode() {
          return EasySSLProtocolSocketFactory.class
               .hashCode();
     }

}
