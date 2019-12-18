<!--
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
-->
# Apache Shiro labs

This project is an example to show how to use Apache Shiro for a set of common use cases.


## Test Instructions

This instructions show you how to try on the resources from karaf-security project.

### Building

```
git clone https://github.com/fpapon/shiro-labs.git
cd shiro-labs
mvn -Drat.skip=true -DskipTests install
```

### Install Features

*Access Karaf console, add repo and install feature*

```
feature:repo-add mvn:fr.openobject.shiro.labs/karaf-features/1.0.0-SNAPSHOT/xml/features 
feature:install shiro-labs-security
```

### Config Keys and Account

*Generate private and public keys, and set properties*

Where '$KARAF_HOME' is the Karaf Framework path.

```
shiro-labs:generate-keys
```

Copy private and public key, then set security.privateKey and security.publicKey properties on $KARAF_HOME/etc/fr.openobject.labs.shiro.karaf.security.cfg

*Create an user account*

```
jdbc:execute jdbc/shiro "insert into SHIRO.USER_ACCOUNT(password, username, id, salt)values('karaf', 'karaf', '1', '1234')"
```

### Generate token

*Generate token for user 'karaf' created*

```
shiro-labs:token-create karaf karaf
```
 
### Validate token

*Try token*
Where '$TOKEN' is the string generated from previous step, replace it.

```
shiro-labs:token-validate $TOKEN
```

### Generate and Validate a token via REST service

*Generate a token*

```
curl -v -X POST -F 'username=karaf' -F 'password=karaf' http://localhost:8181/cxf/shiro-authenticate/token
```

*Validate a token*
Where '$TOKEN' is a string generate previous. 

```
curl -v -H 'Authorization: Bearer $TOKEN' http://localhost:8181/cxf/shiro-authenticate/validate
```

