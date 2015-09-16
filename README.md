Restlet 2.3 Cient Certificate usage
-----------------------------------

This project contains example code showing how one `pfx` certificate file can be used
to create HTTPS connections with the client sending a certificate to the server.

In this case the `pfx` file contains a CA root-certificate and a related client certificate.
The methods in the class `SslUtils` 
(listed [here](https://github.com/intercommit/restlet-clientcert/tree/master/src/main/java/com/descartes/restlet/clientcert))
provide tools to de-construct the certificate file and reconstruct KeysStores and TrustStores which can be used by both servers and clients.

The configuration for the client using `SslUtils` is shown in `ClientSslContextFactory`.  
The configuration for the server using `SslUtils` is shown in `ServerSslContextFactory`.

**Building**

 * Download this project as zip-file and extract the zip-file to a convenient location.
 * Install `com.descartes:appboot:1.1.3.GH`. You can use `lib/install-appboot.bat` in this project. Appboot is part of the [basic-jsp-embed](https://github.com/intercommit/basic-jsp-embed) project and used in this project to start and run the server and client next to each other. 
 * Run `mvn clean package` in this projects home-folder.

**Running**

 * Open a command prompt, go to `target/test-classes` and run `runserver.bat`
 * Open another command prompt, go to `target/test-classes` and run `runclient.bat`
 * Press `ctrl-C` to stop the server in the shell running `runserver.bat`. 

