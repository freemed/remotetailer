REMOTETAILER
============

Author: jeff@freemedsoftware.org

Building
--------

To build a fat jar, use:

```
mvn package
```

Syntax
------

```
java [-Dusername=(http user) -Dpassword=(http password)] -jar remotetailer-VERSION.jar URL [URL ...]
```

Configuration
-------------

Importing a key into the packaged keystore:

```
keytool -importkeystore -srckeystore pkcs12.p12 -srcstoretype PKCS12 -deststoretype JKS -destkeystore src/main/resources/keystore.jks
```

If the keystore doesn't exist or is invalid, client keys will be skipped.

