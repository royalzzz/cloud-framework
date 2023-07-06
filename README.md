# Cloud Framework

## Overview

__I have no time to write this, imagine by yourself.😄__

+ auth-server 7001
+ gateway-server 7777 (unused)
+ message-parent
  + message-api
  + message-resource 7002
+ user-parent
  + user-api
  + user-resource 7003

Just run `auth-server`, `message-resource`, `user-resource`.

## Ready

### Database

```bash
docker run -d --name postgres -e POSTGRES_PASSWORD=dotdot -e PGDATA=/var/lib/postgresql/data/pgdata -v /docker/pgsql:/var/lib/postgresql/data -p 5432:5432 postgis/postgis
```


```sql
create database cloud-auth;
```

> Table will be created by jpa update ddl.

import demo clients data `./docs/demo-clients.sql`

### Redis

```bash
docker run -d --privileged=true --name redis -p 6379:6379 redis
```

### Modify application.yml

you know 127.0.0.1.

## Test

### 1. login

_POST_ http://127.0.0.1:7001/loginByUsernamePassword?username=user&password=password

_POST_ http://127.0.0.1:7001/loginByPhonePassword?phone=user&password=password

### 2. oauth get pkce code

_POST_ http://127.0.0.1:7001/oauth2/authorize?response_type=code&client_id=message-client&scope=openid&redirect_uri=http://127.0.0.1:7001/code/callback&grant_type=authorization_code&client_secret=secret&code_challenge=6akqLtDVNzKsE7AxonsHGBQjHIYzyfQYRMy6iE1IKxY&code_challenge_method=S256

`code_challenge` should be generated from http://127.0.0.1:7001/code/encode?code_verifier=ABCDEFG

### 3. oauth get access token & open id

_POST_ http://127.0.0.1:7001/oauth2/token?client_id=message-client&redirect_uri=http://127.0.0.1:7001/code/callback&grant_type=authorization_code&code=asg62f08_FRoTqNVtnJ24sfxU-cWsoDE8fCs9F5T-o0v1d0uoX5H62j3dgieE9Z8DQFw4-7COll-Ny4fl2p30O3AN4reqgM68DyiYtGTx22TImY35MyRKHFnthRrvmZE&code_verifier=ABCDEFG

`code` was pkce code

### 4. request resource server message

_GET_ http://127.0.0.1:7002/auth

with Bearer Token 👆

### 5. request resource server user (restTemplate get resource message)

_GET_ http://127.0.0.1:7003/user

with Bearer Token 👆

### 6. logout

http://127.0.0.1:7001/connect/logout?id_token_hint=id_token