package com.descartes.restlet.clientcert;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.restlet.data.Parameter;
import org.restlet.engine.ssl.SslContextFactory;
import org.restlet.util.Series;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientSslContextFactory extends SslContextFactory {

	private static final Logger log = LoggerFactory.getLogger(ClientSslContextFactory.class);
	
	protected KeyManager[] kms;
	protected TrustManager[] tms;

	public void init(String certFileName, char[] certFilePwd) throws Exception {
		
		log.debug("Loading certificates from [" + certFileName + "] and using " 
				+ (certFilePwd != null && certFilePwd.length > 0 ? "a" : "no") + " password.");
		Path certFilePath = Paths.get(Thread.currentThread().getContextClassLoader().getResource(certFileName).toURI());
		KeyManagerFactory kmf = SslUtils.loadKeyStore(certFilePath, certFilePwd);
		kms = kmf.getKeyManagers();
		/*
		List<X509Certificate> certs = SslUtils.getClientCaCerts(kmf.getKeyManagers());
		TrustManagerFactory tmf = SslUtils.createTrustStore("caicit", certs.get(0));
		tms = tmf.getTrustManagers();
		*/
		tms = new TrustManager[1];
		tms[0] = new TrustServerCertAlways();
	}

	@Override
	public void init(Series<Parameter> parameters) {
		log.debug("Not using parameters to initialize client SSL Context factory.");
	}

	@Override
	public SSLContext createSslContext() throws Exception {

		SSLContext ctx = SSLContext.getInstance(SslUtils.DEFAULT_SSL_PROTOCOL);
		ctx.init(kms, tms, null);
		return ctx;
	}
	
	static class TrustServerCertAlways implements X509TrustManager {

		@Override public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			log.debug("Trusting all client certificates.");
		}

		@Override public void checkServerTrusted(X509Certificate[] arg0, String arg1)	throws CertificateException {
			log.debug("Trusting all server certificates.");
		}

		@Override public X509Certificate[] getAcceptedIssuers() {
			log.debug("No accepted issuers.");
			return null;
		}
	}

}
