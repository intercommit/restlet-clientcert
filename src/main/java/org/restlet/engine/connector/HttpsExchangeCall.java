package org.restlet.engine.connector;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.restlet.Server;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsExchange;

/**
 * The default {@link HttpExchangeCall} fails to extract certificates from the SSL connection.
 * This class implements {@link #getCertificates()} to extract certificates.
 */
@SuppressWarnings("restriction")
public class HttpsExchangeCall extends HttpExchangeCall {

	private static final Logger log = LoggerFactory.getLogger(HttpsExchangeCall.class);

    private final HttpsExchange sexchange;

    public HttpsExchangeCall(Server server, HttpExchange exchange) {
        this(server, exchange, true);
    }

	public HttpsExchangeCall(Server server, HttpExchange exchange, boolean confidential) {
		super(server, exchange, confidential);
		if (exchange instanceof HttpsExchange) {
			sexchange = (HttpsExchange) exchange;
		} else {
			sexchange = null;
		}
	}

	@Override
    public List<Certificate> getCertificates() {
		
		if (sexchange == null) {
			log.debug("Cannot extract peer certificates from unsecure connection.");
			return null;
		}
		Certificate[] certs = null;
		try {
			certs = sexchange.getSSLSession().getPeerCertificates();
			if (log.isDebugEnabled()) {
				log.debug("Found " + (certs == null ? "no" : Integer.toString(certs.length)) + " peer certificate(s).");
			}
		} catch (Exception e) {
			log.debug("Unable to find peer certificates - " + e);
		}
		List<Certificate> lcerts = null;
		if (certs != null) {
			lcerts = new ArrayList<Certificate>();
			for (int i = 0; i < certs.length; i++) {
				lcerts.add(certs[i]);
			}
		}
        return lcerts;
    }

}
