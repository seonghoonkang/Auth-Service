CREATE INDEX oat_token_id on oauth_access_token(token_id);
CREATE INDEX oat_user_name on oauth_access_token(user_name);
CREATE INDEX oat_client_id on oauth_access_token(client_id);
CREATE INDEX oat_refresh_token on oauth_access_token(refresh_token);
CREATE INDEX oft_token_id on oauth_refresh_token(token_id);