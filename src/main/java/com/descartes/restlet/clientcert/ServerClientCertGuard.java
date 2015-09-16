package com.descartes.restlet.clientcert;

import java.security.cert.X509Certificate;

import org.restlet.Context;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.security.CertificateAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logs the user-name found in a client certificate. 
 */
public class ServerClientCertGuard extends CertificateAuthenticator {
	
	private static final Logger log = LoggerFactory.getLogger(ServerClientCertGuard.class);

    public ServerClientCertGuard(Context context) {
		super(context);
	}

	@Override
    protected boolean authenticate(Request request, Response response) {
    	
		boolean authenticated = super.authenticate(request, response);
		if (authenticated && log.isDebugEnabled()) {
			if (request.getClientInfo().getUser() == null) {
				log.debug("Client certificate authenticated but no user found.");
			} else {
				String name = request.getClientInfo().getUser().getName();
				if (request.getClientInfo().getCertificates().get(0) instanceof X509Certificate) {
					String emailAddress = SslUtils.getClientEmailAddress((X509Certificate)request.getClientInfo().getCertificates().get(0));
					if (emailAddress != null) {
						name = emailAddress;
					}
				}
				log.debug("User found: {}", name);
            }
		}
		return authenticated;
    }

}
