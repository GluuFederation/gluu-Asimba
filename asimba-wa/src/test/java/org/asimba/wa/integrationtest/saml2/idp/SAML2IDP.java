/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2014 Asimba
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see www.gnu.org/licenses
 * 
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package org.asimba.wa.integrationtest.saml2.idp;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;

import org.apache.commons.codec.binary.Base64;
import org.asimba.wa.integrationtest.server.AsimbaWaDerbyDb;
import org.asimba.wa.integrationtest.util.AbstractHttpClientServerTest;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class SAML2IDP extends AbstractHttpClientServerTest {

	private static final Logger _logger = LoggerFactory.getLogger(SAML2IDP.class);
	
	private SAMLIDPHandler _samlIDPHandler;
	private String _entityId;
	private String _metadataUrl;
	
	
	public SAML2IDP(String entityId, SslContextFactory sslContextFactory, IUserInfoProvider userInfoProvider,
			IResponseContextProvider responseContextProvider) throws Exception
	{
		super(sslContextFactory);
		_entityId = entityId;
		
		// Start up Jetty Embedded
		_samlIDPHandler = new SAMLIDPHandler(_entityId, userInfoProvider, responseContextProvider); 
		start(_samlIDPHandler);
		_samlIDPHandler.setServerBase(getServerBase(""));
		
		// _samlIDPHandler.
		
		// Dynamically establish metadata endpoint
		_metadataUrl = getServerBase("/metadata");
		
		_logger.info("Started SAML2IDP '{}' with Metadata URL '{}'", _entityId, _metadataUrl);

	}
	
	
	public void setKeysAndCertificates(String keystoreFilename, String keyStorePassword, String keyAlias, String keyPassword)
	{
		_samlIDPHandler.setKeyConfig(keystoreFilename, keyStorePassword, keyAlias, keyPassword);
	}
	
	public String getCertificate()
	{
		return _samlIDPHandler.getPEMEncodedCertificate();
	}
	
	
	/**
	 * Establish the full qualified URI to an endpoint of the local running 
	 * HTTP server instance
	 * 
	 * @param path path relative to the Client Servlet root; empty string returns root context, i.e. http://localhost:8201
	 * @return
	 */
	private String getServerBase(String path)
	{
		String host = "localhost";
        int port = _connector.getLocalPort();
        
        return _scheme + "://" + host + ":" + port + path;
	}

	
	
	/**
	 * Register the SAML2 IDP directly in the asimba-wa database<br/>
	 * This adds records to:<br/>
	 * <ul>
	 * <li>saml2orgs ; adding the requestor</li>
	 * </ul>
	 * The metadata-url is established dynamically to end up in our local servlet (SAMLIDPHandler)
	 */
	public void registerWithAsimba() throws Exception
	{
		String sql;
		
		// Make sure that the requestor is not registered:
		unregister();
		
		Base64 encoder = new Base64();
		
		MessageDigest dig = MessageDigest.getInstance("SHA-1");
        String sourceId = encoder.encodeToString(dig.digest(_entityId.getBytes("UTF-8")));
        boolean acsIndex = false;
        boolean scoping = false;
        boolean nameIdPolicy = false;
        String nameIdFormat= "";
        boolean allowCreate = true;
        boolean avoidSubjConf = false;
        boolean disableSSO = false;
        
		sql = "INSERT INTO saml2_orgs "+
				" (id,sourceid,friendlyname,metadata_url,metadata_timeout,metadata_file,enabled,acs_index,scoping, " +
				" nameidpolicy,allow_create,nameidformat,avoid_subjconf,disable_sso,date_last_modified) " +
				" VALUES (" +
				"'"+_entityId+"', " +
				"'"+sourceId+"', " +
				"'Friendly "+_entityId+"', " +
				"'"+_metadataUrl+"', " +
				"5000, " +
				"null, " +
				"true, " +
				Boolean.toString(acsIndex) + "," +
				Boolean.toString(scoping) + "," +
				Boolean.toString(nameIdPolicy) + "," +
				Boolean.toString(allowCreate) + "," +
				"'"+nameIdFormat+"', " +
				Boolean.toString(avoidSubjConf) + "," +
				Boolean.toString(disableSSO) + "," +
				"CURRENT_TIMESTAMP" +
				")";
				
		String sqlPrepare = "INSERT INTO saml2_orgs "+
		" (id,sourceid,friendlyname,metadata_url,metadata_timeout,metadata_file,enabled,acs_index,scoping, " +
		" nameidpolicy,allow_create,nameidformat,avoid_subjconf,disable_sso,date_last_modified) " +
		" VALUES (?,?,?,?,?,?,?,?,?,"+
		"?,?,?,?,?,?)";
		
		
		try (Connection c = AsimbaWaDerbyDb.getInstance().getConnection();
				PreparedStatement pstmt = c.prepareCall(sqlPrepare))
				{
			pstmt.setString(1, _entityId);
			pstmt.setBytes(2, sourceId.getBytes("UTF-8"));
			pstmt.setString(3, "'Friendly "+_entityId);
			pstmt.setString(4, _metadataUrl);
			pstmt.setInt(5, 5000);
			pstmt.setString(6, null);
			pstmt.setBoolean(7, true);
			pstmt.setBoolean(8, acsIndex);
			pstmt.setBoolean(9, scoping);
			pstmt.setBoolean(10, nameIdPolicy);
			pstmt.setBoolean(11, allowCreate);
			pstmt.setString(12, nameIdFormat);
			pstmt.setBoolean(13, avoidSubjConf);
			pstmt.setBoolean(14, disableSSO);
			pstmt.setTimestamp(15, new Timestamp(System.currentTimeMillis()));
			
			int i = pstmt.executeUpdate();
			_logger.info("executeUpdate returned {}", i);
			
				}
		finally {}
		
		
		_logger.info("Registering SAML2 IDP '{}':\n{}", _entityId, sql);
		
		// AsimbaWaDerbyDb.getInstance().executeSql(sql);
	}
	
	
	/**
	 * Remove the requestor with configured EntityId from the Asimba Requestor-database<br/>
	 * <br/>
	 * Attempts to delete from database, even if requestor did not exist.
	 */
	public void unregister()
	{
		String sql;
		
		// assert requestor can be added:
		sql = "DELETE FROM saml2_orgs WHERE id='"+_entityId+"'";
		_logger.info("Cleaning SAML2 IDP '{}':\n{}", _entityId, sql);
		AsimbaWaDerbyDb.getInstance().executeSql(sql);
		
	}
	
}
