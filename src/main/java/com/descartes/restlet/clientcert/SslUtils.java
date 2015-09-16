package com.descartes.restlet.clientcert;

import java.io.InputStream;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SslUtils {

	private static final Logger log = LoggerFactory.getLogger(SslUtils.class);
	
	/**
	 * List of SSL protocols (SSLv3, TLSv1.2, etc.). See also {@link SslUtils#DEFAULT_SSL_PROTOCOL}.
	 * <br>Documented at http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SSLContext
	 */
	public static final String[] SSL_PROTOCOLS = new String[] { "SSL", "SSLv2", "SSLv3", "TLS", "TLSv1", "TLSv1.1", "TLSv1.2" };
	
	/**
	 * Default SSL protocol to use ("TLSv1.2").
	 */
	public static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";

	/**
	 * Creates a default SSL context with an empty key-store and the default JRE trust-store.
	 */
	public static SSLContext createDefaultSslContext() throws Exception {
		return createSslContext(null, null, null, null);
	}
	/**
	 * Creates a default SSL socket factory.
	 * <br>All system properties related to trust/key-stores are ignored, eveything is done programmatically.
	 * This is because the Sun implementation reads the system-properties once and then caches the values.
	 * Among other things, this fails the unit tests.
	 * <br>For reference, the system properties (again, NOT USED):
	 * <br> - javax.net.ssl.trustStore (default cacerts.jks)
	 * <br> - javax.net.ssl.trustStorePassword
	 * <br>and for client certificate:
	 * <br> - javax.net.ssl.keyStore (set to "agent-cert.p12")
	 * <br> - javax.net.ssl.keyStoreType (set to "pkcs12")
	 * <br> - javax.net.ssl.keyStorePassword
	 * <br>See for a discussion:
	 * http://stackoverflow.com/questions/6340918/trust-store-vs-key-store-creating-with-keytool
	 * <br>See for client certificates in Java:
	 * http://stackoverflow.com/questions/1666052/java-https-client-certificate-authentication
	 * @param keyStoreFileName The name (ending with pfx) of the file with client certificates.
	 * @param trustStoreFileName The name (ending with jks) of the Java KeyStore with trusted (root) certificates.
	 * @return null or the SSLContext.
	 */
	public static SSLContext createSslContext(Path keyStoreFile, String keyStorePwd, 
			Path trustStoreFile, String trustStorePwd) throws Exception {
		return createSslContext(keyStoreFile, keyStorePwd, trustStoreFile, trustStorePwd, DEFAULT_SSL_PROTOCOL);
	}

	/**
	 * See {@link #createSslContext(Path, String, Path, String)}.
	 * @param sslProtocol a value from {@link #SSL_PROTOCOLS}.
	 */
	public static SSLContext createSslContext(Path keyStoreFile, String keyStorePwd, 
			Path trustStoreFile, String trustStorePwd, String sslProtocol) throws Exception {
		
        KeyManagerFactory kmf = loadKeyStore(keyStoreFile, keyStorePwd == null ? null : keyStorePwd.toCharArray());
		TrustManagerFactory tmf = loadTrustStore(trustStoreFile, trustStorePwd == null ? null : trustStorePwd.toCharArray());
        //set an Authenticator to generate username and password
        SSLContext ctx = SSLContext.getInstance(sslProtocol);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
	}

	/**
	 * Calls {@link #createSslContextFromClientKeyStore(Path, String, Path, String)} with the {@link #DEFAULT_SSL_PROTOCOL}.
	 */
	public static SSLContext createSslContextFromClientKeyStore(Path keyStoreFile, String keyStorePwd, 
			String caAlias) throws Exception {
		return createSslContextFromClientKeyStore(keyStoreFile, keyStorePwd, caAlias, DEFAULT_SSL_PROTOCOL);
	}

	/**
	 * Creates a SSL context from the given key-store containing a client certificate and a (CA) root certificate.
	 * The root certificate is set in the trust-store of the SSL context.  
	 * @param keyStoreFileName key-store file name (ending with .pfx).
	 * @param keyStorePwd key-store password
	 * @param caAlias the alias to use for the CA (root) certificate (e.g. "mycaroot").
	 * @param sslProtocol the ssl-protocol (e.g. {@link #DEFAULT_SSL_PROTOCOL}).
	 */
	public static SSLContext createSslContextFromClientKeyStore(Path keyStoreFile, String keyStorePwd, 
			String caAlias, String sslProtocol) throws Exception {
	
        KeyManagerFactory kmf = loadKeyStore(keyStoreFile, keyStorePwd == null ? null : keyStorePwd.toCharArray());
        List<X509Certificate> certs = getClientCaCerts(kmf.getKeyManagers());
        if (certs.size() < 1) {
        	throw new Exception("Cannot find CA (root) certificate in key-managers from key store "  + keyStoreFile.getFileName());
        }
        TrustManagerFactory tmf = createTrustStore(caAlias, certs.get(0));
        SSLContext ctx = SSLContext.getInstance(sslProtocol);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
	}

	public static KeyManagerFactory loadKeyStore(Path storeFile) throws Exception {
		return loadKeyStore(storeFile, null);
	}

	public static KeyManagerFactory loadKeyStore(Path storeFile, char[] storePwd) throws Exception {
		return loadKeyStore(storeFile, storePwd, null, null);
	}

	public static KeyManagerFactory loadKeyStore(Path storeFile, char[] storePwd, 
			String storeType, String algorithm) throws Exception {
		
		KeyManagerFactory kmf = null;
		if (storeFile == null) {
			kmf = loadKeyStore((InputStream)null, storePwd, storeType, algorithm);
		} else {
			try (InputStream storeIn = Files.newInputStream(storeFile)) {
				kmf = loadKeyStore(storeIn, storePwd, storeType, algorithm);
				log.info("Initialized certificate key-store from ["  + storeFile.getFileName() + "]");
			}
		}
		return kmf;
	}
	
	public static KeyManagerFactory loadKeyStore(InputStream storeIn, char[] storePwd, 
			String storeType, String algorithm) throws Exception {
		
		if (storePwd == null && storeIn != null) {
			storePwd = "changeit".toCharArray();
			log.debug("Using default key store password.");
		}
		if (storeType == null) {
			storeType = "pkcs12";
			log.debug("Using default key store type " + storeType);
		}
		if (algorithm == null) {
			algorithm = KeyManagerFactory.getDefaultAlgorithm(); // "SunX509"
			log.debug("Using default key store algorithm " + algorithm);
		}
		KeyManagerFactory kmf = null;
       	KeyStore keyStore = loadStore(storeIn, storePwd, storeType);
		kmf = KeyManagerFactory.getInstance(algorithm);
		kmf.init(keyStore, storePwd);
		if (storeIn == null) {
			log.info("Initialized a default certificate key-store");
		}
		return kmf;
	}
	
	/**
	 * Creates a trust-store with the given CA (root) certificate.
	 * @param certAlias the alias for the certificate (e.g. "mycaroot")
	 * @param caCert the CA (root) certificate
	 * @return an initialized trust manager factory.
	 */
	public static TrustManagerFactory createTrustStore(String certAlias, X509Certificate caCert) throws Exception {
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load((LoadStoreParameter)null); // must initialize the key-store
		ks.setCertificateEntry(certAlias, caCert);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);
		return tmf;
	}

	public static TrustManagerFactory loadTrustStore(Path storeFile) throws Exception {
		return loadTrustStore(storeFile, null);
	}

	public static TrustManagerFactory loadTrustStore(Path storeFile, char[] storePwd) throws Exception {
		return loadTrustStore(storeFile, storePwd, null, null);
	}

	public static TrustManagerFactory loadTrustStore(Path storeFile, char[] storePwd, 
			String storeType, String algorithm) throws Exception {
		
		TrustManagerFactory tmf = null;
		if (storeFile == null) {
			tmf = loadTrustStore((InputStream)null, storePwd, storeType, algorithm);
		} else {
			try (InputStream storeIn = Files.newInputStream(storeFile)) {
				tmf = loadTrustStore(storeIn, storePwd, storeType, algorithm);
			}
			log.info("Initialized certificate trust-store from ["  + storeFile.getFileName() + "]");
		}
		return tmf;
	}

	public static TrustManagerFactory loadTrustStore(InputStream storeIn, char[] storePwd, 
			String storeType, String algorithm) throws Exception {
		
		if (storePwd == null && storeIn != null) {
			storePwd = "changeit".toCharArray();
			log.debug("Using default trust store password.");
		}
		if (storeType == null) {
			storeType = KeyStore.getDefaultType();
			log.debug("Using default trust store type " + storeType);
		}
		if (algorithm == null) {
			algorithm = TrustManagerFactory.getDefaultAlgorithm();
			log.debug("Using default trust store algorithm " + algorithm);
		}
		TrustManagerFactory tmf = null;
		KeyStore trustStore = loadStore(storeIn, storePwd, storeType);
		tmf = TrustManagerFactory.getInstance(algorithm);
		tmf.init(trustStore);
  		if (storeIn == null) {
   			log.info("Initialized a default certificate trust-store");
   		}
		return tmf;
	}
	
	/**
	 * Creates a default trust store containing the JRE certificates in {@code JAVA_HOME\lib\security\cacerts.jks}
	 * <br>To view loaded certificates call 
	 * <br>{@code System.setProperty("javax.net.debug", "ssl,trustmanager");}
	 * <br>before calling this method.
	 */
	public static TrustManagerFactory createDefaultTrustStore() throws Exception {
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init((KeyStore)null);
		return tmf;
	}

	/**
	 * @param in if null, null is returned.
	 */
	public static KeyStore loadStore(InputStream in, char[] pwd, String type) throws Exception {
		
		if (in == null) {
			return null;
		}
		KeyStore ks = KeyStore.getInstance(type);
		ks.load(in, pwd);
		return ks;
	}

	/**
	 * Finds any CA (root) certificates present in client certificate chains.
	 * <br>Uses {@link #getClientAliases(KeyManager)}
	 * @param kms key-managers (from a key-store).
	 * @return an empty list or a list containing CA (root) certificates.
	 */
	public static List<X509Certificate> getClientCaCerts(KeyManager[] kms) {
		
		List<X509Certificate> caCerts = new LinkedList<X509Certificate>();
		for (int i = 0; i < kms.length; i++) {
			if (!(kms[i] instanceof X509KeyManager)) {
				continue;
			}
			X509KeyManager km = (X509KeyManager) kms[i];
			List<String> aliases = getClientAliases(km);
			for (String alias: aliases) {
				X509Certificate[] cchain = km.getCertificateChain(alias);
				if (cchain == null || cchain.length < 2) {
					continue;
				}
				// first certificate in chain is the user certificate
				// last certificate is the CA (root certificate).
				caCerts.add(cchain[cchain.length-1]);
				if (log.isDebugEnabled()) {
					log.debug("Found 1 root certificate from client certificate alias " + alias);
				}
			}
		}
		return caCerts;
	}

	/**
	 * List of key types for client certificate aliases, used in {@link #getAliases(KeyManager)}
	 * <br>List is documented at 
	 * http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#jssenames
	 */
	public static final String[] KEY_TYPES = new String[] {"RSA", "DSA", "DH_RSA", "DH_DSA", "EC", "EC_EC", "EC_RSA" };
	
	/**
	 * Searches for client aliases in the given key-manager. 
	 * Does nothing when the given key-manager is not an instance of {@link X509KeyManager}. 
	 * @return an empty list or a list containing client aliases found in the key-manager.
	 */
	public static List<String> getClientAliases(KeyManager keyManager) {
		
		List<String> aliases = new LinkedList<String>();
		if (keyManager instanceof X509KeyManager) {
			X509KeyManager km = (X509KeyManager) keyManager;
			for (String keyType: KEY_TYPES) {
				String[] kmAliases = km.getClientAliases(keyType, null);
				if (kmAliases != null) {
					for (String alias: kmAliases) {
						if (!isEmpty(alias)) {
							aliases.add(alias);
						}
					}
				}
			} // for keytypes
		}
		return aliases;
	}
	
	/**
	 * Extracts the email-address from client certificates.
	 * Does nothing when the given key-managers are not an instance of {@link X509KeyManager}. 
	 * <br>Uses {@link #getClientAliases(KeyManager)} and {@link #getClientEmailAddress(KeyManager, List)}.
	 * @param kms key-managers (from a key-store).
	 * @return an empty list or a list of email-addresses found in the subjects of client certificates.
	 */
	public static List<String> getClientEmailAddress(KeyManager[] kms) {
		
		List<String> emailAddresses = new LinkedList<String>();
		for (int i = 0; i < kms.length; i++) {
			if (!(kms[i] instanceof X509KeyManager)) {
				continue;
			}
			X509KeyManager km = (X509KeyManager) kms[i];
			List<String> aliases = getClientAliases(km);
			if (aliases.size() > 0) {
				if (log.isDebugEnabled()) {
					log.debug("Checking email address for aliases " + aliases);
				}
			}
			emailAddresses.addAll(getClientEmailAddress(km, aliases));
		}
		return emailAddresses;
	}
	
	/**
	 * Searches for client email-address in the client certificates subject-name of the given key-manager. 
	 * Does nothing when the given key-manager is not an instance of {@link X509KeyManager}. 
	 * <br>Uses {@link #getClientEmailAddress(X509Certificate)}.
	 * @param keyManager the key-manager.
	 * @param aliases a list of client certificate aliases part of the key-manager (see also {@link #getClientAliases(KeyManager)}). 
	 * @return an empty list or a list containing client email addresses found in the subject of the client certificate(s) in the key-manager.
	 */
	public static List<String> getClientEmailAddress(KeyManager keyManager, List<String> aliases) {
		
		List<String> emailAddresses = new LinkedList<String>();
		if (keyManager instanceof X509KeyManager) {
			X509KeyManager km = (X509KeyManager) keyManager;
			for (String alias: aliases) {
				X509Certificate[] cchain = km.getCertificateChain(alias);
				if (cchain == null || cchain.length < 1) {
					continue;
				}
				// first certificate in chain is the user certificate
				String certEmailAddress = getClientEmailAddress(cchain[0]);
				if (certEmailAddress != null) {
					if (log.isDebugEnabled()) {
						log.debug("Found email address for alias " + alias + ": " + certEmailAddress);
					}
					emailAddresses.add(certEmailAddress);
				}
			} // for aliases
		}
		return emailAddresses;
	}
	
	/**
	 * The OID of the email-address attributes in a client certificate.
	 */
	public static final String X509_EMAIL_ADDRESS_OID = "1.2.840.113549.1.9.1";
	
	/**
	 * The name mapped to the {@link #X509_EMAIL_ADDRESS_OID}.
	 */
	public static final String X509_EMAIL_ADDRESS_ATTR_NAME = "EMAILADDRESS"; 
	
	/**
	 * Unmodifiable map containing the {@link #X509_EMAIL_ADDRESS_OID} as key and {@link #X509_EMAIL_ADDRESS_ATTR_NAME}
	 * as value. Used by {@link #getClientEmailAddress(KeyManager, List)}. 
	 */
	@SuppressWarnings("serial")
	public static final Map<String, String> X509_EMAIL_ATTR_MAP = 
		Collections.unmodifiableMap(
			new HashMap<String, String>() {{
				put(X509_EMAIL_ADDRESS_OID, X509_EMAIL_ADDRESS_ATTR_NAME);
			}}
		);
	
	/**
	 * {@link #X509_EMAIL_ADDRESS_ATTR_NAME} appended with the {@code =} sign.
	 * <br>Used in {@link #X509_SUBJECT_EMAIL_MATCHER} and to parse the email-address value.
	 */
	public static final String X509_SUBJECT_EMAIL_ATTR = X509_EMAIL_ADDRESS_ATTR_NAME + "=";
	
	/**
	 * Matcher to extract the email-address from a client certificate subject.
	 * Used by {@link #getClientEmailAddress(KeyManager, List)} (matching is synchronized on the matcher itself).
	 */
	public static final Matcher X509_SUBJECT_EMAIL_MATCHER = Pattern.compile(X509_SUBJECT_EMAIL_ATTR + "(.*?),").matcher("");

	/**
	 * Extracts the email-address from the certificate subject.
	 * <br>See also {@link #X509_EMAIL_ATTR_MAP} and {@link #X509_SUBJECT_EMAIL_MATCHER}.
	 * @return null or the found email-address.
	 */
	public static String getClientEmailAddress(X509Certificate clientCert) {
		
		X500Principal x500Subject = clientCert.getSubjectX500Principal();
		String subjectName = x500Subject.getName(X500Principal.RFC2253, X509_EMAIL_ATTR_MAP);
		String certEmailAddress = null;
		Matcher m = X509_SUBJECT_EMAIL_MATCHER;
		synchronized (m) {
			if (m.reset(subjectName).find()) {
				certEmailAddress = subjectName.substring(m.start(), m.end());
			}
		}
		if (certEmailAddress == null) {
			log.debug("No email address found in client certificate subject: " + subjectName);
		} else {
			certEmailAddress = certEmailAddress.substring(X509_SUBJECT_EMAIL_ATTR.length(), certEmailAddress.length() - 1);
		}
		return certEmailAddress;
	}

	/**
	 * Sets the default authenticator which can be used for example with http-request that require basic authoriation.
	 * <br>See also {@link Authenticator#setDefault(Authenticator)}.
	 */
	public static void setDefaultAuthenticator(final String userName, final char[] pwd) throws Exception {
		
        Authenticator auth = new Authenticator() {
        	@Override
        	protected PasswordAuthentication getPasswordAuthentication() {
        		return new PasswordAuthentication(userName, pwd);
        	}
        };
        Authenticator.setDefault(auth);
	}

	/**
	 * @return true if s is not null and not empty after trimming, false otherwise.
	 */
	public static boolean isEmpty(String s) { return (s == null || s.trim().isEmpty()); }

}
