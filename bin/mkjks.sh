#!/bin/bash

SECRET=secret

#openssl req -newkey rsa:2048 -new -x509 -days 3652 -nodes -outform der -out $1.crt -keyout $1.pem
openssl req -newkey rsa:2048 -new -x509 -days 3652 -nodes -outform pem -out $1.crt -keyout $1.pem


#cat $1.der | head -n -1 | tail -n +2 | tr -d '\n'; echo
#cat $1.crt | head -n -1 | tail -n +2 | tr -d '\n'; echo

# Create pkcs12 version of cert
 winpty openssl pkcs12 -export -in $1.crt -inkey $1.pem -out $1.p12

# import the certificate
keytool -import -v -trustcacerts -alias $1-sp-crt -file $1.crt -keystore $1.jks -storepass $SECRET

# import the private key
keytool -importkeystore -srckeystore $1.p12 -srcstoretype PKCS12 -destkeystore $1.jks -deststoretype JKS -storepass $SECRET 

# change the alias of the private key, defaults to '1'
keytool -changealias -alias 1 -destalias $1-sp -keystore $1.jks -storepass $SECRET

# add the ssodev.crt if present
if [ -f ssodev.crt ] 
    then
	keytool -import -v -trustcacerts -alias ssodev-idp -file ssodev.crt -keystore $1.jks -storepass $SECRET
fi

# list the keystore
keytool -list -keystore $1.jks -rfc -storepass $SECRET
