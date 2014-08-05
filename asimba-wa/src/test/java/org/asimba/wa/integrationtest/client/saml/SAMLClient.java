package org.asimba.wa.integrationtest.client.saml;

import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;

import javax.xml.stream.XMLStreamException;

import org.asimba.wa.integrationtest.server.AsimbaWaDerbyDb;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebRequest;


public class SAMLClient extends AbstractHttpClientServerTest {
	
	private static final Logger _logger = LoggerFactory.getLogger(SAMLClient.class);
	
	private SAMLSPHandler _samlSPHandler;
	private String _entityId;
	private String _acsUrl;
	private String _metadataUrl;
	
	
	public SAMLClient(String entityId, SslContextFactory sslContextFactory) throws Exception
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
	 * Register the requestor dynamically, its metadata??
	 * @param requestorPool
	 */
	public void registerInRequestorPool(String requestorPool)
	{
		String sql;
		
		// assert requestor can be added:
		sql = "DELETE FROM requestorpool_requestor WHERE id='"+_entityId+"'";
		_logger.info("Cleaning requestor:\n{}", sql);
		AsimbaWaDerbyDb.getInstance().executeSql(sql);
		
		sql = "DELETE FROM requestorpool_requestor_properties WHERE requestor_id='"+_entityId+"'";
		_logger.info("Cleaning requestor properties:\n{}", sql);
		AsimbaWaDerbyDb.getInstance().executeSql(sql);
		
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
			String url = webSSOUrl + "?SAMLRequest="+
					AuthnRequest.getRidOfCRLF(URLEncoder.encode(authnRequestMessage, "UTF-8"));
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
				
		if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding))
		{
			// GET-request to http://server/websso?SAMLRequest=....bse64-deflated-encoded....
			// AuthRequest.getRidOfCRLF(URLEncoder.encode(authReq.getRequest(AuthRequest.base64),"UTF-8"));
			String url = webSSOUrl + "?SAMLRequest="+
					AuthnRequest.getRidOfCRLF(URLEncoder.encode(authnRequestMessage, "UTF-8"));
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
