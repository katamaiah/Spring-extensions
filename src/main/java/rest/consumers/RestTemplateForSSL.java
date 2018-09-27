package rest.consumers;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * Access Https URL's with Rest template with and without validating trust store
 * 
 * @author Katamaiah
 *
 */
public class RestTemplateForSSL {
	
	public static final String httpsURL = "https://localhost:8443";

	/**
	 * Uncomment each line by sequence to test and see the response . startup
	 * wildfly and localhost:8080 and localhost:8443 can be used for testing
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		
		// accessSSLusingRestTemplate(httpsURL); // throws sslhandshake problem
		// accessSSLusingRestTemplatewithHttpClient(httpsURL, true); // resttemplate fixed to trust all certificates
		// accessSSLusingHttpGet(httpsURL);// use httpget instead of resttemplate
	}

	/**
	 * Plain approach
	 * 
	 * @throws Exception
	 */
	public static void accessSSLusingRestTemplate(String httpsURL) throws Exception {

		ResponseEntity<String> response = new RestTemplate().exchange(httpsURL, HttpMethod.GET, null, String.class);
		System.out.println("Rest template without ssl :" + response.getStatusCode().value());
	}

	/**
	 * Rest template customized to use httpclient with ssl and trust all for
	 * selfsigned certificates
	 * 
	 * @throws Exception
	 */
	public static void accessSSLusingRestTemplatewithHttpClient(String httpsURL, boolean selfsigned) throws Exception {

		ResponseEntity<String> response = new RestTemplate(getRequestFactory(selfsigned)).exchange(httpsURL,
				HttpMethod.GET, null, String.class);
		System.out.println("Rest template with ssl: " + response.getStatusCode().value());
	}

	/**
	 * Access Rest API using HttpGet
	 * 
	 * @throws Exception
	 */
	public static void accessSSLusingHttpGet(String httpsURL) throws Exception {
		SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, (certificate, authType) -> true)
				.build();
		CloseableHttpClient client = HttpClients.custom().setSSLContext(sslContext)
				.setSSLHostnameVerifier(new NoopHostnameVerifier()).build();
		HttpGet httpGet = new HttpGet(httpsURL);
		httpGet.setHeader("Accept", "application/xml");
		HttpResponse response = client.execute(httpGet);
		System.out.println("Rest template with ssl and httpget:" + response.getStatusLine().getStatusCode());
	}

	/**
	 * Get request for self signed
	 * 
	 * @param selfsigned
	 * @return
	 * @throws KeyManagementException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws Exception
	 */
	public static HttpComponentsClientHttpRequestFactory getRequestFactory(boolean selfsigned)
			throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, Exception {
		HttpComponentsClientHttpRequestFactory requestFactory = null;
		SSLConnectionSocketFactory sslConnectionSocketFactory = selfsigned ? createSSLSocketFactoryForSelfSigned()
				: createSSLSocketFactoryWithTrustStoreValidation(true, "secret", "secret");

		CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslConnectionSocketFactory).build();
		requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClient);
		return requestFactory;
	}

	/**
	 * SSLConnectionFactory for Self signed to trust all certificates
	 * 
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 */
	private static SSLConnectionSocketFactory createSSLSocketFactoryForSelfSigned()
			throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		TrustStrategy acceptingTrustStrategy = new TrustStrategy() {
			public boolean isTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
				return true;
			}

			@Override
			public boolean isTrusted(java.security.cert.X509Certificate[] chain, String authType)
					throws java.security.cert.CertificateException {
				// TODO Auto-generated method stub
				return true;
			}
		};
		SSLContext sslContext = null;
		SSLConnectionSocketFactory csf = null;
		// no truststore is passed . null passed in place of trust store
		sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
		csf = new SSLConnectionSocketFactory(sslContext);
		return csf;
	}

	/**
	 * Create ssl factory by loading the truststore .This is under construction
	 * 
	 * @param useKeyStoreToConnect
	 * @param keyStorePath
	 * @param keyStorePassword
	 * @return
	 * @throws Exception
	 */
	private static SSLConnectionSocketFactory createSSLSocketFactoryWithTrustStoreValidation(
			boolean useKeyStoreToConnect, String keyStorePath, String keyStorePassword) throws Exception {
		SSLConnectionSocketFactory csf = null;
		// Only load KeyStore when it's needed to connect to an external IP, SSLContext
		// is fine with KeyStore being null otherwise.
		KeyStore trustStore = null;
		if (useKeyStoreToConnect) {
			// trustStore = KeyStoreLoader.loadKeyStore(keyStorePath, keyStorePassword);
		}

		TrustStrategy validatingTrustStrategy = new TrustStrategy() {
			public boolean isTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
				return true;
			}

			@Override
			public boolean isTrusted(java.security.cert.X509Certificate[] chain, String authType)
					throws java.security.cert.CertificateException {
				// TODO Auto-generated method stub
				return true;
			}
		};

		SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(trustStore, validatingTrustStrategy)
				.loadKeyMaterial(trustStore, keyStorePassword.toCharArray())
				.setSecureRandom(new java.security.SecureRandom()).build();
		csf = new SSLConnectionSocketFactory(sslContext);
		return csf;
	}

}
