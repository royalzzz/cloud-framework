insert into client (id,authorization_grant_types,client_authentication_methods,client_id,client_id_issued_at,client_name,client_secret,client_secret_expires_at,client_settings,post_logout_redirect_uris,redirect_uris,scopes,token_settings) values
	 ('666666','authorization_code','client_secret_basic','public-client',NULL,'PKCE-Service','{noop}secret',NULL,'{"@class": "java.util.Collections$UnmodifiableMap","settings.client.require-proof-key": true,"settings.client.require-authorization-consent": false}','http://127.0.0.1:7001/logout','http://127.0.0.1:7003/authorized,http://127.0.0.1:70037003/login/oauth2/code/public-client-oidc','openid,profile','{"@class": "java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens": true}'),
	 ('123456','refresh_token,client_credentials,authorization_code','none','message-client',NULL,'message-resource-server','{bcrypt}$2a$10$kV.fVf67hk9Ccwf0l1HjJeYtskj9rKTS/I2XOdWw8q6rdr2yHTGoq',NULL,'{"@class": "java.util.Collections$UnmodifiableMap","settings.client.require-proof-key": true,"settings.client.require-authorization-consent": false}','http://127.0.0.1:7001/logout','http://127.0.0.1:7003/authorized,http://127.0.0.1:7003/login/oauth2/code/message-client-oidc,http://127.0.0.1:7003/authorized,http://127.0.0.1:7003/login/oauth2/code/message-client-oidc,http://127.0.0.1:7001/code/callback,http://127.0.0.1:7001/code/callback','openid,profile,message.read,message.write','{
  "@class": "java.util.Collections$UnmodifiableMap",
  "settings.token.reuse-refresh-tokens": true,
  "settings.token.authorization-code-time-to-live": [
    "java.time.Duration",
    3600
  ],
  "settings.token.id-token-signature-algorithm": [
    "org.springframework.security.oauth2.jose.jws.SignatureAlgorithm",
    "RS256"
  ],
  "settings.token.access-token-time-to-live": [
    "java.time.Duration",
    3000.000000000
  ],
  "settings.token.refresh-token-time-to-live": [
    "java.time.Duration",
    3600.000000000
  ],
  "settings.token.access-token-format": {
    "@class": "org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat",
    "value": "self-contained"
  }
}');
