CREATE TABLE session (
  id varchar(24) NOT NULL,
  tgt_id varchar(172) DEFAULT NULL,
  expiration timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  state BIGINT NOT NULL DEFAULT 0,
  requestor_id varchar(255) NOT NULL,
  url text,
  forced_authenticate SMALLINT NOT NULL,
  sessionuser text,
  attributes blob,
  forced_userid text,
  locale blob,
  selected_authn_profile blob,
  authn_profiles blob,
  passive SMALLINT DEFAULT 0,
  PRIMARY KEY (id)
);


CREATE TABLE tgt (
  id varchar(172) NOT NULL,
  expiration timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  tgtuser text,
  authn_profile text,
  authn_profile_ids text,
  requestor_ids text,
  attributes text,
  PRIMARY KEY (id),
  KEY tgt_expiration_idx (expiration)
);

CREATE TABLE alias_store_sp (
  tgt_id varchar(172) NOT NULL,
  sp_id varchar(255) NOT NULL,
  aselect_credentials varchar(350) DEFAULT NULL,
  session_index varchar(343) DEFAULT NULL,
  transient_user_id varchar(256) DEFAULT NULL,
  persistent_user_id varchar(255) DEFAULT NULL,
  unspecified11_user_id varchar(255) DEFAULT NULL,
  unspecified20_user_id varchar(255) DEFAULT NULL,
  email_user_id varchar(255) DEFAULT NULL,
  PRIMARY KEY (tgt_id,sp_id),
  KEY alias_store_sp_index_aselect_credentials_sp_id (aselect_credentials,sp_id),
  KEY alias_store_sp_index_email_sp_id (email_user_id,sp_id),
  KEY alias_store_sp_index_persistent_sp_id (persistent_user_id,sp_id),
  KEY alias_store_sp_index_session_index_sp_id (session_index,sp_id),
  KEY alias_store_sp_index_tgt_alias_sp_id (tgt_id,sp_id),
  KEY alias_store_sp_index_tgt_id (tgt_id),
  KEY alias_store_sp_index_transient_sp_id (transient_user_id,sp_id),
  KEY alias_store_sp_index_unspecified11_sp_id (unspecified11_user_id,sp_id),
  KEY alias_store_sp_index_unspecified20_sp_id (unspecified20_user_id,sp_id)
);

CREATE TABLE alias_store_idp (
  tgt_id varchar(172) NOT NULL,
  idp_id varchar(255) NOT NULL,
  aselect_credentials varchar(512) DEFAULT NULL,
  session_index varchar(343) DEFAULT NULL,
  transient_user_id varchar(256) DEFAULT NULL,
  persistent_user_id varchar(255) DEFAULT NULL,
  unspecified11_user_id varchar(255) DEFAULT NULL,
  unspecified20_user_id varchar(255) DEFAULT NULL,
  email_user_id varchar(255) DEFAULT NULL,
  PRIMARY KEY (tgt_id,idp_id),
  KEY alias_store_idp_index_aselect_credentials_idp_id (aselect_credentials,idp_id),
  KEY alias_store_idp_index_email_idp_id (email_user_id,idp_id),
  KEY alias_store_idp_index_persistent_idp_id (persistent_user_id,idp_id),
  KEY alias_store_idp_index_session_index_idp_id (session_index,idp_id),
  KEY alias_store_idp_index_tgt_alias_idp_id (tgt_id,idp_id),
  KEY alias_store_idp_index_tgt_id (tgt_id),
  KEY alias_store_idp_index_transient_idp_id (transient_user_id,idp_id),
  KEY alias_store_idp_index_unspecified11_idp_id (unspecified11_user_id,idp_id),
  KEY alias_store_idp_index_unspecified20_idp_id (unspecified20_user_id,idp_id)
);

CREATE TABLE requestorpool_authnprofile (
  authn_profile_id varchar(48) NOT NULL,
  pool_id varchar(48) NOT NULL,
  order_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (authn_profile_id,pool_id),
  UNIQUE KEY order_id (order_id)
) ENGINE=MyISAM AUTO_INCREMENT=10 DEFAULT CHARSET=latin1;

CREATE TABLE requestorpool_pool (
  id varchar(48) NOT NULL,
  friendlyname varchar(255) NOT NULL,
  enabled tinyint(1) DEFAULT 1,
  preauthz_profile_id varchar(48) DEFAULT NULL,
  postauthz_profile_id varchar(48) DEFAULT NULL,
  forced tinyint(1) DEFAULT 0,
  releasepolicy varchar(48) DEFAULT NULL,
  date_last_modified datetime DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE requestorpool_properties (
  pool_id varchar(48) NOT NULL,
  name varchar(255) NOT NULL,
  value varchar(255) NOT NULL,
  PRIMARY KEY (pool_id,name)
);

CREATE TABLE requestorpool_requestor (
  id varchar(255) NOT NULL,
  pool_id varchar(48) NOT NULL,
  friendlyname varchar(255) NOT NULL,
  enabled tinyint(1) DEFAULT 1,
  date_last_modified datetime DEFAULT NULL,
  PRIMARY KEY (id),
  KEY inx_rr_pool_id (pool_id)
);

CREATE TABLE requestorpool_requestor_properties (
  requestor_id varchar(255) NOT NULL,
  name varchar(255) NOT NULL,
  value varchar(255) NOT NULL,
  PRIMARY KEY (requestor_id,name),
  KEY inx_rrp_requestor_id (requestor_id) USING BTREE
);

CREATE TABLE authn_profile (
  id varchar(48) NOT NULL,
  friendlyname varchar(255) NOT NULL,
  enabled tinyint(1) DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE authn_profile_properties ( 
	profile_id varchar(48) NOT NULL,
	name varchar(255) NOT NULL,
	value varchar(255) NOT NULL,
	PRIMARY KEY(profile_id,name)
);

CREATE TABLE authn_method ( 
	id varchar(48) NOT NULL,
	profile_id varchar(48) NOT NULL,
	order_id SERIAL NOT NULL,		
	PRIMARY KEY(id,profile_id)  
);

CREATE TABLE attributerelease_policy (
  id varchar(48) NOT NULL,
  friendlyname varchar(255) DEFAULT NULL,
  enabled tinyint(1) DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE attributerelease_expression (
  policy_id varchar(48) NOT NULL,
  expression varchar(255) NOT NULL,
  PRIMARY KEY (policy_id,expression)
);

CREATE TABLE authz_profile (
  id varchar(48) NOT NULL,
  friendlyname varchar(255) DEFAULT NULL,
  enabled tinyint(1) DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE authz_method (
  id varchar(48) NOT NULL,
  profile_id varchar(48) NOT NULL,
  order_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (id,profile_id),
  UNIQUE KEY order_id (order_id)
);

CREATE TABLE ssoquery_whitelist (
  item varchar(255) NOT NULL,
  PRIMARY KEY (item)
);

CREATE TABLE users (
  userid VARCHAR(64) NOT NULL,
  password VARCHAR(64) NOT NULL,
  PRIMARY KEY (userid)
);

CREATE TABLE artifact
(
  id character varying(60) NOT NULL,
  issuer character varying(255) DEFAULT NULL::character varying,
  relyingparty character varying(255) DEFAULT NULL::character varying,
  expiration timestamp without time zone NOT NULL,
  message text,
  CONSTRAINT artifact_pkey PRIMARY KEY (id)
);


-- for SAML2AuthenticationMethod:
CREATE TABLE `saml2_orgs` (
  `id` varchar(255) NOT NULL,
  `sourceid` text NOT NULL,
  `friendlyname` varchar(255) NOT NULL,
  `metadata_url` varchar(255) DEFAULT NULL,
  `metadata_timeout` int(11) NOT NULL DEFAULT '-1',
  `metadata_file` varchar(255) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT '1',
  `acs_index` tinyint(1) NOT NULL DEFAULT '1',
  `scoping` tinyint(1) NOT NULL DEFAULT '1',
  `nameidpolicy` tinyint(1) NOT NULL DEFAULT '1',
  `allow_create` tinyint(1) DEFAULT NULL,
  `nameidformat` varchar(255) DEFAULT NULL,
  `avoid_subjconf` tinyint(1) NOT NULL DEFAULT '0',
  `disable_sso` tinyint(1) DEFAULT '0',
  `date_last_modified` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) DEFAULT CHARSET=utf8;
