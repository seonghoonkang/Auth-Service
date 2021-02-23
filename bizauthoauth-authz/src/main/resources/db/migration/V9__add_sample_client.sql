INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types, authorities, web_server_redirect_uri, autoapprove)
VALUES ('cool_app_id', 'groups', '$2a$10$HjC4gZZYgVIO.Hxn0h9w1em/rJ2StyvcHbU8cpcMUK5D8OIL.Zv.e', 'read',
'client_credentials,implicit,authorization_code,refresh_token', 'ROLE_TOKEN_CHECKER', 'http://localhost:8081', 'true');

INSERT INTO oauth_client_details (client_id, client_secret, authorities)
VALUES ('vootservice', '$2a$10$HjC4gZZYgVIO.Hxn0h9w1em/rJ2StyvcHbU8cpcMUK5D8OIL.Zv.e','ROLE_TOKEN_CHECKER');