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
package org.asimba.wa.integrationtest.client.saml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.StringUtils;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jetty Handler that provides the following services:<br/>
 * <ul>
 * <li>AssertionConsumerService handler on /acs</li>
 * <li>Metadata handler on /metadata</li>
 * <li>later: ArtifactResolutionService handler on /artifact</li>
 * </ul>
 * @author mdobrinic
 *
 */
public class SAMLSPHandler extends AbstractHandler {
	private static final Logger _logger = LoggerFactory.getLogger(SAMLSPHandler.class);

	private String _serverBase;
	private String _entityId;
	
	private Response _samlResponse;
	
	
	public SAMLSPHandler(String entityId)
	{
		_entityId = entityId;
		_serverBase = null;
	}
	
	public void setServerBase(String serverBase)
	{
		_serverBase = serverBase;
	}
	
	@Override
	public void handle(String target, Request baseRequest,
			HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		
		_logger.info("handle() called:");
		_logger.info("  target: {}", target);
		_logger.info("  baseRequest: {}", baseRequest.getContextPath());
		_logger.info("  queryString: {}", baseRequest.getQueryString());
		
		if ("/metadata".equals(target))
		{
			handleMetadata(response);
		}
		else if ("/acs".equals(target))
		{
			handleAssertionConsumerService(request, response);
		}
		else if ("/artifact".equals(target))
		{
			handleArtifactResolutionService();
		}
		else
		{
			_logger.error("Unknown target requested: {}", target);
		}

		baseRequest.setHandled(true);
	}
	
	
	private void handleMetadata(HttpServletResponse response) throws IOException
	{
		_logger.info("Providing metadata for {}", _entityId);
		
		String metadata = 
						"<!-- " +
						"   Unsigned metadata for AsimbaSimpleSP demo application "+
						"	Part of AsimbaSSO Baseline distribution "+
						"--> "+
						"<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\""+_entityId+"\">"+
						"  <md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol\">" +
						"    <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\""+_serverBase+"/acs"+"\" index=\"0\"/>" +
						"    <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:1.0:profiles:browser-post\" Location=\""+_serverBase+"/acs"+"\" index=\"1\"/>"+
						"  </md:SPSSODescriptor>"+
						"  <md:Organization>"+
						"    <md:OrganizationName xml:lang=\"en\">Asimba</md:OrganizationName>"+
						"    <md:OrganizationDisplayName xml:lang=\"en\">Asimba - Serious Open Source SSO</md:OrganizationDisplayName>"+
						"    <md:OrganizationURL xml:lang=\"en\">http://www.asimba.org</md:OrganizationURL>"+
						"  </md:Organization>"+
						"  <md:ContactPerson contactType=\"technical\">"+
						"    <md:GivenName>Asimba Developer</md:GivenName>"+
						"    <md:EmailAddress>info@asimba.org</md:EmailAddress>"+
						"  </md:ContactPerson> "+
						"</md:EntityDescriptor>";
		_logger.debug("Providig metadata\n{}", metadata);
		response.getWriter().print(metadata);
	}
	
	
	private void handleAssertionConsumerService(HttpServletRequest request, HttpServletResponse response) throws IOException
	{
		_logger.info("Handling assertion consumer for {}", _entityId);
		Response samlResponse = new Response();
		
		// Get response from request (must be in POST-data)
		String samlResponseString = request.getParameter("SAMLResponse");
		if (samlResponseString == null)
		{
			_logger.error("Did not receive SAMLResponse parameter");
			return;
		}
		
		// Base64-decode the incoming message
		samlResponseString = StringUtils.newStringUtf8(
				Base64.decode(samlResponseString));
		
		_logger.info("Received SAMLResponse:\n{}", samlResponseString);
		
		samlResponse.loadResponse(samlResponseString);
		
		_logger.info("Succesfully received unverified SAMLResponse message");
		_samlResponse = samlResponse;
		
		response.getWriter().print("OK");
	}
	
	
	public Response getSAMLResponse() 
	{
		return _samlResponse;
	}
	

	private void handleArtifactResolutionService()
	{
		_logger.info("Handling artifact resolution for {}", _entityId);
	}
	
}
