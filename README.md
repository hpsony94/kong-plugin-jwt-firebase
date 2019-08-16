## JWT Firebase custom [Kong](https://www.getkong.org) plugins

Contents:
#### JWT Firbase plugin
This plugin is basically to verify the JWT Firbase Token following the [firebase doc](https://firebase.google.com/docs/auth/admin/verify-id-tokens)
What we need to run this plugin is just the firebase project name.

#### Installtion
[Plugin development](https://docs.konghq.com/0.14.x/plugin-development/distribution/) by Kong
###### Install the plugin into Kong
```bash
luarocks install https://github.com/hpsony94/kong-plugin-jwt-firebase/releases/download/1.0.0-1/kong-plugin-jwt-firebase-1.0.0-1.all.rock
```
###### Load the plugin by kong.conf file
- By editting the kong.conf file 
```
plugins = bundled, jwt-firebase
```

#### How it works
According to the [firebase doc](https://firebase.google.com/docs/auth/admin/verify-id-tokens) this plugin verifies the header, payload, and signature of the ID token.
- Verify that the alg is "RS256"
- Verify that the kid must correspond too one of the pubic key listed at https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
- Verify that the exp must be in the future. (UNIX epoch)
- Verify that the aud must be your Firebase project ID
- Verify that the iss must be "https://securetoken.google.com/<projectId>", where <projectId> is the same project ID used for aud above.
- Verify that the sub must be non-empty string and must be the uid of the user or device.
and Finally, ensure that the ID token was signed by the private key corresponding to the token's kid claim. 
Grab the public key from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com 
and use a JWT library to verify the signature. 

#### Plugin pamameters
```sh
#TODO : Let's write something
```

#### Configuration
This is the example of using the JWT firebase plugin to verify JWT token in Firebase project id chatq-dev
- Create a service
```sh
$ curl -i -X POST localhost:8001/services \
    --data "name=test" \
    --data "url=http://httpbin.org"
```
- Create a route
```sh
$ curl -i -X POST localhost:8001/services/test/routes \
    --data "name=test" \
    --data "paths[]=/test"
```
- Add the JWT Firebase plugin to test route
```sh
$ curl -i -X POST localhost:8001/routes/test/plugins \
    --data "name=jwt-firebase" \
    --data "config.project_id=chatq-dev"
```

Now you send the requests throuhgh, only tokens signed by Firebase project "chatq-dev" will work:
```sh
$ curl -ik -X GET \
    --url https://localhost:8443/test \
    --header 'Authorization: Bearer <token-id> '
```
This plugin also supports legacy authenticaion without Bearer
```sh
$ curl -ik -X GET \
    --url https://localhost:8443/test \
    --header 'Authorization: <token-id> '
```

#### TODO: Improvement or Tech debt
TBD

#### How to release
Create the Lua rock in current directory:
```sh
$ luarock make
$ luarocks pack kong-plugin-jwt-firebase
```

#### Acknowledgements
- [Kong: Plugin Development Guide](https://getkong.org/docs/latest/plugin-development/)
- [Kong: Development](https://github.com/Mashape/kong/blob/master/README.md#development)
- [Kong: Test Suite](https://github.com/Mashape/kong#tests)
- [Kong: Configuration](kong-docs-config)
- [Luarocks: Kong search](https://luarocks.org/search?q=kong)
- [Luarocks: Best Practices for Makefiles](https://github.com/keplerproject/luarocks/wiki/Recommended-practices-for-Makefiles)
- [Luarocks: Creating a rock](https://github.com/keplerproject/luarocks/wiki/Creating-a-rock)

#### License
```
Copyright 2016-2019 Kong Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
