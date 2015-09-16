package org.restlet.engine.connector;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.restlet.Server;
import org.restlet.data.Protocol;
import org.restlet.engine.ssl.SslContextFactory;
import org.restlet.engine.ssl.SslUtils;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * Updated copy from
 * <br>https://github.com/restlet/restlet-framework-java/blob/2.3/modules/org.restlet/src/org/restlet/engine/connector/HttpsServerHelper.java
 * <br>Only 1 line (number 68 in this source file) is updated to use a reference to this class and {@link HttpsExchangeCall}.
 */
@SuppressWarnings("restriction")
public class HttpsServerHelper2 extends NetServerHelper {

	private volatile HttpsServer server;

    public HttpsServerHelper2(Server server) {
        super(server);
        getProtocols().add(Protocol.HTTPS);
    }

    @Override
    public void start() throws Exception {

    	SslContextFactory sslContextFactory = SslUtils
                .getSslContextFactory(this);
        SSLContext sslContext = sslContextFactory.createSslContext();
        String addr = getHelped().getAddress();

        if (addr != null) {
            InetAddress iaddr = InetAddress.getByName(addr);
            setAddress(new InetSocketAddress(iaddr, getHelped().getPort()));
        } else {
            int port = getHelped().getPort();
            if (port > 0) {
                setAddress(new InetSocketAddress(getHelped().getPort()));
            }
        }

        this.server = HttpsServer.create(new InetSocketAddress(getHelped()
                .getPort()), 0);
        final SSLParameters sslParams = sslContext.getDefaultSSLParameters();
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
           @Override 
           public void configure(HttpsParameters params) {
                params.setSSLParameters(sslParams);
            }
        });

        server.createContext("/", new HttpHandler() {
            @Override 
            public void handle(HttpExchange httpExchange) throws IOException {
// the line below is updated
                HttpsServerHelper2.this.handle(new HttpsExchangeCall(getHelped(),
                        httpExchange, true));
            }
        });
        server.setExecutor(createThreadPool());
        server.start();

        setConfidential(true);
        setEphemeralPort(server.getAddress().getPort());
        super.start();
    }

    @Override
    public synchronized void stop() throws Exception {
        super.stop();
        this.server.stop(0);
    }

}
