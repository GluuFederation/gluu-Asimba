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
package org.asimba.wa.integrationtest.saml2.sp;

import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;

import javax.xml.stream.XMLStreamException;

import org.asimba.wa.integrationtest.saml2.model.AuthnRequest;
import org.asimba.wa.integrationtest.saml2.model.Response;
import org.asimba.wa.integrationtest.server.AsimbaWaDerbyDb;
import org.asimba.wa.integrationtest.util.AbstractHttpClientServerTest;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebRequest;


public class SAML2SP extends AbstractHttpClientServerTest {
	
	private static final Logger _logger = LoggerFactory.getLogger(SAML2SP.class);
	
	private SAMLSPHandler _samlSPHandler;
	private String _entityId;
	private String _acsUrl;
	private String _metadataUrl;
	
	
	public SAML2SP(String entityId, SslContextFactory sslContextFactory) throws Exception
	{
        super(sslContextFactory);
		
		_entityId = entityId;
		
		// Start up Jetty Embedded
		_samlSPHandler = new SAMLSPHandler(_entityId); 
		start(_samlSPHandler);
		_samlSPHandler.setServerBase(getServerBase(""));
		
		// Dynamically establish ACS endpoint
		_acsUrl = getServerBase("/acs");
		_metadataUrl = getServerBase("/metadata");
		
		_logger.info("Started SAMLClient '{}' with ACS URL '{}'", _entityId, _acsUrl);
	}
	

	/**
	 * Register the requestor directly in the asimba-wa database<br/>
	 * This adds records to:<br/>
	 * <ul>
	 * <li>requestorpool_requestor ; adding the requestor</li>
	 * <li>requestorpool_requestor_properties ; adding signing=false and metadata.url/timeout properties</li>
	 * </ul>
	 * The metadata-url is established dynamically to end up in our local servlet (SAMLSPHandler)
	 * @param requestorPool
	 */
	public void registerInRequestorPool(String requestorPool)
	{
		String sql;
		
		// Make sure that the requestor is not registered:
		unregister();
		
		// Create new requestors:
		sql = "INSERT INTO requestorpool_requestor(id, pool_id, friendlyname, enabled, date_last_modified) VALUES" +
		" ('"+_entityId+"', '"+requestorPool+"', '"+_entityId+" friendlyname', true, CURRENT_TIMESTAMP)";
		_logger.info("Registering requestor:\n{}", sql);
		
		AsimbaWaDerbyDb.getInstance().executeSql(sql);

		sql = "INSERT INTO requestorpool_requestor_properties(requestor_id, name, value) VALUES" +
		" ('"+_entityId+"', 'saml2.signing', 'false'), " +
		" ('"+_entityId+"', 'saml2.metadata.http.url', '"+_metadataUrl+"'), " +
		" ('"+_entityId+"', 'saml2.metadata.http.timeout', '10000') ";
		_logger.info("Registering requestor properties:\n{}", sql);
		
		AsimbaWaDerbyDb.getInstance().executeSql(sql);
		
		_logger.debug("Added requestor {} in requestorpool {}", _entityId, requestorPool);
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
		sql = "DELETE FROM requestorpool_requestor WHERE id='"+_entityId+"'";
		_logger.info("Cleaning requestor:\n{}", sql);
		AsimbaWaDerbyDb.getInstance().executeSql(sql);
		
		sql = "DELETE FROM requestorpool_requestor_properties WHERE requestor_id='"+_entityId+"'";
		_logger.info("Cleaning requestor properties:\n{}", sql);
		AsimbaWaDerbyDb.getInstance().executeSql(sql);
	}
	
	
	
	public void registerProperty(String key, String value)
	{
		String sql;
		sql = "INSERT INTO requestorpool_requestor_properties(requestor_id, name, value) VALUES" +
				" ('"+_entityId+"', '"+key+"', '"+value+"') ";
		_logger.info("Adding requestor property:\n{}", sql);
		AsimbaWaDerbyDb.getInstance().executeSql(sql);
	}
	
	
	public void unregisterProperty(String key)
	{
		String sql;
		sql = "DELETE FROM requestorpool_requestor_properties WHERE requestor_id='"+_entityId+"'"
				+ " AND name = '"+key+"'";
		_logger.info("Cleaning requestor property:\n{}", sql);
		AsimbaWaDerbyDb.getInstance().executeSql(sql);
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
	 * Get Request for requesting an AuthnRequest, using the provided binding
	 * @throws IOException 
	 * @throws XMLStreamException 
	 * 
	 */
	public Request getAuthnRequest(String webSSOUrl, String binding) throws XMLStreamException, IOException
	{
		AuthnRequest authnRequest = new AuthnRequest(_acsUrl, _entityId);
		String authnRequestMessage = authnRequest.getRequest(AuthnRequest.base64);
				
		if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding))
		{
			// GET-request to http://server/websso?SAMLRequest=....bse64-deflated-encoded....
			// AuthRequest.getRidOfCRLF(URLEncoder.encode(authReq.getRequest(AuthRequest.base64),"UTF-8"));
			String url = webSSOUrl + "?SAMLRequest="+URLEncoder.encode(authnRequestMessage, "UTF-8");
			return _client.newRequest(url);
		}
		else if (SAMLConstants.SAML2_POST_BINDING_URI.equals(binding))
		{
			// POST-request to http://server/websso with multipart/form encoded in postbody
			_logger.error("POST binding not yet implemented");
			return null;
		}
		else if (SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(binding))
		{
			// Artifact-request to http://server/websso with Artifact ID
			_logger.error("Artifact binding not yet implemented");
			return null;
		}
		else
		{
			_logger.error("Binding {} not (yet) supported.", binding);
			return null;
		}
	}

	
	public WebRequest getAuthnWebRequest(String webSSOUrl, String binding) throws XMLStreamException, IOException
	{
		AuthnRequest authnRequest = new AuthnRequest(_acsUrl, _entityId);
		String authnRequestMessage = authnRequest.getRequest(AuthnRequest.base64);
		_logger.debug("Message to send:\n{}", authnRequestMessage);
		
		if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding))
		{
			// GET-request to http://server/websso?SAMLRequest=....bse64-deflated-encoded....
			// AuthRequest.getRidOfCRLF(URLEncoder.encode(authReq.getRequest(AuthRequest.base64),"UTF-8"));
			String url = webSSOUrl + "?SAMLRequest="+URLEncoder.encode(authnRequestMessage, "UTF-8");
			return new WebRequest(new URL(url), HttpMethod.GET);
			
		}
		else if (SAMLConstants.SAML2_POST_BINDING_URI.equals(binding))
		{
			// POST-request to http://server/websso with multipart/form encoded in postbody
			_logger.error("POST binding not yet implemented");
			return null;
		}
		else if (SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(binding))
		{
			// Artifact-request to http://server/websso with Artifact ID
			_logger.error("Artifact binding not yet implemented");
			return null;
		}
		else
		{
			_logger.error("Binding {} not (yet) supported.", binding);
			return null;
		}
	}

	
	public Response getReceivedResponse()
	{
		// Get this from the SAMLSP Handler:
		return _samlSPHandler.getSAMLResponse();
	}
}
