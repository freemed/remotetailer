package org.freemedsoftware.util.remotetailer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.HeadMethod;

public class RemoteTailer {

	private static HashMap<String, Long> pos = new HashMap<String, Long>();

	private static int SLEEP_TIME = 5;

	private RemoteTailer() {
	}

	/**
	 * @param args
	 * @throws InterruptedException
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableKeyException
	 * @throws KeyManagementException
	 */
	public static void main(String[] args) throws InterruptedException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException, UnrecoverableKeyException,
			KeyManagementException {

		HttpClient client = new HttpClient(
				new MultiThreadedHttpConnectionManager());
		client.getHttpConnectionManager().getParams().setConnectionTimeout(
				10000);
		client.getParams().setAuthenticationPreemptive(true);

		char[] passwKey = "changeit".toCharArray();
		KeyStore ts = KeyStore.getInstance("PKCS12");

		Provider provBC = Security.getProvider("BC");
		ClassLoader classLoader = new RemoteTailer().getClass()
				.getClassLoader();
		SSLContext sslContext = SSLContext.getInstance("TLS");
		try {
			ts.load(classLoader.getResourceAsStream("keystore.jks"), passwKey);
			KeyManagerFactory tmf = KeyManagerFactory.getInstance("X.509", provBC);
			tmf.init(ts, passwKey);
			sslContext.init(tmf.getKeyManagers(), null, null);
			SSLSocketFactory factory = sslContext.getSocketFactory();
			HttpsURLConnection.setDefaultSSLSocketFactory(factory);
		} catch (IOException ioe) {
			System.out.println("Ignoring keystore, load error");
		} catch (IllegalArgumentException iae) {
			System.out.println("Ignoring keystore, load error");
		}

		/*
		 * SSLSocket socket = (SSLSocket) factory.createSocket(host,Port); //
		 * Create the ServerSocket String[] suites =
		 * socket.getSupportedCipherSuites();
		 * socket.setEnabledCipherSuites(suites); //start handshake
		 * socket.startHandshake();
		 */

		// Set credentials
		if (System.getProperty("username") != null && System.getProperty("password") != null) {
			Credentials defaultcreds = new UsernamePasswordCredentials(System
					.getProperty("username"), System.getProperty("password"));
			client.getState().setCredentials(AuthScope.ANY, defaultcreds);
		} else {
			System.out.println("No credentials given.");
		}

		/*
		 * client .getHostConfiguration() .setHost( new URL(args[0]).getHost(),
		 * 443, new Protocol( "https", (ProtocolSocketFactory) new
		 * EasySSLProtocolSocketFactory(), 443));
		 */

		if (args.length == 0) {
			System.err.println("No URLs specified!");
			System.exit(1);
		}

		List<String> urls = Arrays.asList(args);
		for (String url : urls) {
			pos.put(url, getContentLength(client, url));
		}

		System.out.println("Sleeping for " + SLEEP_TIME + " seconds");
		Thread.sleep(SLEEP_TIME * 1000);

		while (true) {
			for (String url : urls) {
				long newpos = getContentLength(client, url);
				if (newpos > pos.get(url)) {
					// Show what we've got
					System.out.println(" --> " + url + " <--");
					System.out.println(getContentRange(client, url, pos
							.get(url), newpos));

					// Push the new value in
					pos.put(url, newpos);
				} else if (newpos < pos.get(url)) {
					// This is to handle file "resets" or rotations

					// Show from 0 to here
					System.out.println(" --> " + url + " <--");
					System.out.println(getContentRange(client, url, 0, newpos));

					// Push the new value in
					pos.put(url, newpos);
				}
			}
			Thread.sleep(SLEEP_TIME * 1000);
		}
	}

	private static long getContentLength(HttpClient client, String url) {
		long l = 0;
		HeadMethod m = new HeadMethod(url);
		m.setFollowRedirects(true);
		try {
			int resultCode = client.executeMethod(m);
			// System.out.println("[" + resultCode + "] Content-length: "
			// + m.getResponseContentLength());
			l = Long
					.parseLong(m.getResponseHeader("Content-Length").getValue());
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			m.releaseConnection();
		}
		return l;
	}

	private static String getContentRange(HttpClient client, String url,
			long start, long end) {
		String result = "";
		GetMethod m = new GetMethod(url);
		m.setRequestHeader(new Header("Range", "bytes=" + start + "-" + end));
		m.setFollowRedirects(true);
		try {
			client.executeMethod(m);
			result = m.getResponseBodyAsString();
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			m.releaseConnection();
		}
		return result;
	}
}
