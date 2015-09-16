package com.descartes.restlet.clientcert;

import org.slf4j.bridge.SLF4JBridgeHandler;

public class Constants {

	/** File has to be in class-path, else loading will fail. */
	public static final String CERT_TEST_FILE_NAME = "test18.pfx";
	public static final char[] CERT_TEST_PWD = "33333333".toCharArray();
	/** This can be any value, as long as it is somewhat unique. */
	public static final String CERT_CA_ALIAS = "myrootca";
	public static final int PORT_TEST = 8183;
	
	public static void configureLogging() {
		
		SLF4JBridgeHandler.removeHandlersForRootLogger();
		SLF4JBridgeHandler.install();
		System.setProperty("org.restlet.engine.loggerFacadeClass", "org.restlet.ext.slf4j.Slf4jLoggerFacade");
	}
}
