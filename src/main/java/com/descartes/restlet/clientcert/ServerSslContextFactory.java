package com.descartes.restlet.clientcert;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.restlet.data.Parameter;
import org.restlet.engine.ssl.DefaultSslContext;
import org.restlet.engine.ssl.DefaultSslContextFactory;
import org.restlet.util.Series;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates a SSL Context programmatically.
 */
public class ServerSslContextFactory extends DefaultSslContextFactory {
	
	private static final Logger log = LoggerFactory.getLogger(ServerSslContextFactory.class);

	protected DefaultSslContext wrappedCtx;

	public void init(String certFileName, char[] certFilePwd) throws Exception {
		
		if (log.isDebugEnabled()) {
			log.debug("Loading certificates from [" + certFileName + "] and using " 
					+ (certFilePwd != null && certFilePwd.length > 0 ? "a" : "no") + " password.");
		}
		Path certFilePath = Paths.get(Thread.currentThread().getContextClassLoader().getResource(certFileName).toURI());
		KeyManagerFactory kmf = SslUtils.loadKeyStore(certFilePath, certFilePwd);
		KeyManager[] kms = kmf.getKeyManagers();
		List<X509Certificate> certs = SslUtils.getClientCaCerts(kmf.getKeyManagers());
		TrustManagerFactory tmf = SslUtils.createTrustStore(Constants.CERT_CA_ALIAS, certs.get(0));
		TrustManager[] tms = tmf.getTrustManagers();
		
		super.setNeedClientAuthentication(true);
		
		SSLContext ctx = SSLContext.getInstance(SslUtils.DEFAULT_SSL_PROTOCOL);
		ctx.init(kms, tms, null);
		wrappedCtx = (DefaultSslContext) createWrapper(ctx);
	}
	
    @Override
    public void init(Series<Parameter> parameters) { 
    	log.debug("Not using parameters to initialize server SSL Context factory.");
    }
	
	@Override
	public SSLContext createSslContext() throws Exception {
		return wrappedCtx;
	}
	
	@Override
    public boolean isNeedClientAuthentication() {
		
		if (log.isDebugEnabled()) {
			//log.debug("Needing client auth: " + super.isNeedClientAuthentication(), new RuntimeException("trace"));
			log.debug("Needing client auth: " + super.isNeedClientAuthentication());
		}
        return super.isNeedClientAuthentication();
    }

}
