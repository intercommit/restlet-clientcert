@echo off
rem %~dp0 is the directory of this script
java -Dapp.name=restlet-clientcert -jar %~dp0lib\appboot.jar %*