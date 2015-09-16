package com.descartes.restlet.clientcert;

import java.util.concurrent.ConcurrentMap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.restlet.Client;
import org.restlet.Context;
import org.restlet.data.MediaType;
import org.restlet.data.Protocol;
import org.restlet.representation.Representation;
import org.restlet.resource.ClientResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RestletClientMain {

	static {
		Constants.configureLogging();
		/*
		 * All SSL debug options are listed at
		 * http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html#Debug
		 */
		// System.setProperty("javax.net.debug", "ssl");
		// System.setProperty("javax.net.debug", "ssl,keymanager");
		// System.setProperty("javax.net.debug", "ssl,trustmanager");
	}

	private static final Logger log = LoggerFactory.getLogger(RestletClientMain.class);

	public static void main(String[] args) {

		try {
			new RestletClientMain().start();
		} catch (Exception e) {
			log.error("Failed to start client.", e);
		}
	}
	
	final String certFileName = Constants.CERT_TEST_FILE_NAME;
	final char[] certFilePwd =  Constants.CERT_TEST_PWD;

	public void start() throws Exception {
		
		Client client = new Client(new Context(), Protocol.HTTPS);
		ConcurrentMap<String, Object> attribs = client.getContext().getAttributes();
		attribs.put("hostnameVerifier", new TrustAllHostnames());
		
		ClientSslContextFactory sslCtx = new ClientSslContextFactory();
		sslCtx.init(certFileName, certFilePwd);
		attribs.put("sslContextFactory", sslCtx);
		
		ClientResource traceText = new ClientResource("https://localhost:" + Constants.PORT_TEST + "/trace");
		traceText.setNext(client);
		Representation result = traceText.get(MediaType.TEXT_PLAIN);
		log.info("Trace text: " + System.lineSeparator() + result.getText());
	}
	
	static class TrustAllHostnames implements HostnameVerifier {

		@Override public boolean verify(String hostname, SSLSession session) {
			log.debug("Trusting all hosts.");
			return true;
		}
	}
	
}
