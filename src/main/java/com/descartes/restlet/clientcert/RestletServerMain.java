package com.descartes.restlet.clientcert;

import java.util.Arrays;
import java.util.concurrent.ConcurrentMap;

import org.restlet.Component;
import org.restlet.Context;
import org.restlet.Server;
import org.restlet.data.Protocol;
import org.restlet.engine.Engine;
import org.restlet.engine.connector.HttpsServerHelper2;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RestletServerMain extends ServerResource {

	static {
		Constants.configureLogging();
	}

	private static final Logger log = LoggerFactory.getLogger(RestletServerMain.class);

	public static void main(String[] args) {

		try {
			new RestletServerMain().start();
		} catch (Exception e) {
			log.error("Failed to start server.", e);
		}
	}
	
	final String certFileName = Constants.CERT_TEST_FILE_NAME;
	final char[] certFilePwd =  Constants.CERT_TEST_PWD;

	public void start() throws Exception {

		Engine.getInstance().getRegisteredServers().add(new HttpsServerHelper2(null));
		Component component = new Component();
		Server server = new Server(
				(Context) null, Arrays.asList(Protocol.HTTPS),
				(String) null, Constants.PORT_TEST, component.getServers().getNext(), 
				HttpsServerHelper2.class.getName()
			);
		component.getServers().add(server);

		ServerSslContextFactory sslCtx = new ServerSslContextFactory();
		sslCtx.init(certFileName, certFilePwd);
		ConcurrentMap<String, Object> attribs = server.getContext().getAttributes();
		attribs.put("sslContextFactory", sslCtx);

		ServerClientCertGuard guard = new ServerClientCertGuard(server.getContext());
		guard.setNext(RestletServerMain.class);
		component.getDefaultHost().attachDefault(guard);
		
		// component.getDefaultHost().attach("/trace", RestletServerMain.class);
		ShutdownHook hook = new ShutdownHook(component);
		Runtime.getRuntime().addShutdownHook(hook);
		try {
			component.start();
		} catch (Exception e) {
			log.error("Server start failed.", e);
			Runtime.getRuntime().removeShutdownHook(hook);
			hook.run();
		}
	}

	@Get("txt")
	public String toString() {
		// Print the requested URI path
		return "Resource URI  : " + getReference() 
				+ '\n' + "Root URI      : " + getRootRef() 
				+ '\n' + "Routed part   : "	+ getReference().getBaseRef() 
				+ '\n' + "Remaining part: " + getReference().getRemainingPart();
	}
	
	static class ShutdownHook extends Thread {
		
		private final Component component;
		
		public ShutdownHook(Component component) {
			super();
			this.component = component;
		}
		
		@Override
		public void run() {
			
			try {
				log.info("Shutting down.");
				component.stop();
				log.info("Shutdown complete.");
			} catch (Exception e) {
				log.error("Shutdown incomplete.", e);
			}
		}
	}
	
}
