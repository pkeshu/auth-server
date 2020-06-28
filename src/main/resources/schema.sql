SET sql_mode = '';
CREATE TABLE IF NOT EXISTS oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256) NOT NULL,
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4000),
  autoapprove VARCHAR(256)
) engine=innodb ;

CREATE TABLE IF NOT EXISTS oauth_client_token (
  token_id VARCHAR(256),
  token LONG VARBINARY,
  authentication_id VARCHAR(256) PRIMARY KEY,
  user_name VARCHAR(256),
  client_id VARCHAR(256)
) engine=innodb ;

CREATE TABLE IF NOT EXISTS oauth_access_token (
  token_id VARCHAR(256),
  token LONG VARBINARY,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication LONG VARBINARY,
  refresh_token VARCHAR(256)
) engine=innodb ;

CREATE TABLE IF NOT EXISTS oauth_refresh_token (
  token_id VARCHAR(256),
  token LONG VARBINARY,
  authentication LONG VARBINARY
) engine=innodb ;

CREATE TABLE IF NOT EXISTS oauth_code (
  code VARCHAR(256), authentication LONG VARBINARY
) engine=innodb ;



CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(256) NOT NULL,
  password VARCHAR(256) NOT NULL,
  enabled BOOLEAN,
  account_non_expired BOOLEAN,
  account_non_locked BOOLEAN,
  credentials_non_expired BOOLEAN,
  UNIQUE KEY unique_username(username)
) engine=innodb ;



CREATE TABLE IF NOT EXISTS authorities (
 id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  authority VARCHAR(256) NOT NULL,
  CONSTRAINT  fk_authorities FOREIGN KEY (user_id) REFERENCES users (id)
) engine=innodb ;