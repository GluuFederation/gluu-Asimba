INSERT INTO authn_method(id, profile_id, order_id) VALUES
('GuestAuthenticationMethod', 'local.guest', 1),
('IdentifyingMethod', 'local.identifying', 2),
('AsimbaUsersXmlPassword', 'local.asimba.passwd', 3),
('SAML2AuthNMethod', 'remote.saml', 4);

INSERT INTO authn_profile(id, friendlyname, enabled) VALUES 
('local.guest', 'Login as guest', true),
('local.identifying', 'Login with provided username (no authentication)', true),
('local.asimba.passwd', 'Login from Asimba userstore with password authentication', true),
('remote.saml', 'Login with remote SAML IDP', true);

-- No AuthorizationMethods just yet
-- INSERT INTO authz_method(id, profile_id, order_id) VALUES (?, ?, ?);

-- No Pre- or Post-AuthorizationProfiles just yet
-- INSERT INTO authz_profile(id, friendlyname, enabled) VALUES (?, ?, ?);

INSERT INTO attributerelease_expression(policy_id, expression) VALUES 
('releasepolicy.all', '*');

INSERT INTO attributerelease_policy(id, friendlyname, enabled) VALUES 
('releasepolicy.all', 'Release all available attributes', true);




-- No RequestorPool Properties just yet (note: in particular this is used for A-Select IDP Profile)
-- INSERT INTO requestorpool_properties(pool_id, name, value) VALUES (?, ?, ?);

INSERT INTO requestorpool_pool(
            id, friendlyname, enabled, preauthz_profile_id, postauthz_profile_id, 
            forced, releasepolicy, date_last_modified) VALUES 
('requestorpool.1', 'Requestor Pool 1', true, null, null, false, 'releasepolicy.all', CURRENT_TIMESTAMP);

INSERT INTO requestorpool_authnprofile(authn_profile_id, pool_id, order_id) VALUES 
('local.guest', 'requestorpool.1', 1),
('local.identifying', 'requestorpool.1', 2),
('local.asimba.passwd', 'requestorpool.1', 3),
('remote.saml', 'requestorpool.1', 4);


INSERT INTO requestorpool_requestor(id, pool_id, friendlyname, enabled, date_last_modified) VALUES 
('urn:asimba:requestor:aselect-test', 'requestorpool.1', 'Test A-Select Requestor', true, CURRENT_TIMESTAMP),
('urn:asimba:requestor:saml-test', 'requestorpool.1', 'Test SAML2 Requestor', true, CURRENT_TIMESTAMP),
('urn:asimba:client:saml-client', 'requestorpool.1', 'SAML-client', true, CURRENT_TIMESTAMP);

INSERT INTO requestorpool_requestor_properties(requestor_id, name, value) VALUES 
('urn:asimba:requestor:aselect-test', 'aselect.app_level', '9'),
('urn:asimba:requestor:saml-test', 'saml2.signing', 'false'),
('urn:asimba:requestor:saml-test', 'saml2.metadata.file', '${webapp.root}/WEB-INF/test-data/metadata-saml-test.xml'),
('urn:asimba:client:saml-client', 'saml2.signing', 'false'),
('urn:asimba:client:saml-client', 'saml2.metadata.file', '${webapp.root}/WEB-INF/test-data/metadata-saml-saml-client.xml');
