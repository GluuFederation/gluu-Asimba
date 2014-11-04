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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLStreamException;

import org.apache.commons.codec.binary.Base64;
import org.asimba.utility.xml.XMLUtils;
import org.asimba.wa.integrationtest.saml.SAMLFailException;
import org.asimba.wa.integrationtest.saml2.model.Assertion;
import org.asimba.wa.integrationtest.saml2.model.AuthnRequest;
import org.asimba.wa.integrationtest.saml2.model.Response;
import org.asimba.wa.integrationtest.saml2.model.SAMLMessage;
import org.asimba.wa.integrationtest.util.SignatureHelper;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alfaariss.oa.OAException;

/**
 * Handle:<br/>
 * <ul>
 * <li>/metadata : deliver EntityDescriptor with IDPSSO that describes this IDP</li>
 * <li>/websso : endpoint that receives an AuthnRequest and immediately provides response</li>
 * </ul>
 * The methods handling might be tweaked, see for more info the specific method.
 * 
 * @author mdobrinic
 *
 */
public class SAMLIDPHandler extends AbstractHandler {

	private static final Logger _logger = LoggerFactory.getLogger(SAMLIDPHandler.class);

	private String _serverBase;
	private String _entityId;

	private SignatureHelper _signatureHelper = null;

	private IUserInfoProvider _userInfoProvider;
	private IResponseContextProvider _responseContextProvider;

	public SAMLIDPHandler(String entityId, IUserInfoProvider userInfoProvider, 
			IResponseContextProvider responseContextProvider)
	{
		_entityId = entityId;
		_serverBase = null;
		_userInfoProvider = userInfoProvider;
		_responseContextProvider = responseContextProvider;
	}

	public void setServerBase(String serverBase)
	{
		_serverBase = serverBase;
	}

	/**
	 * Set keystore filename; must be resolvable in classpath.<br/>
	 * 
	 * @param keystoreFile
	 */
	public void setKeyConfig(String keystoreFile, String keyStorePassword, String keyAlias, String keyPassword)
	{
		InputStream keystoreStream = 
				this.getClass().getClassLoader().getResourceAsStream(keystoreFile);

		if (keystoreStream != null)
		{
			if (_signatureHelper == null)
			{
				_signatureHelper = new SignatureHelper();
			}

			_signatureHelper.setKeystore("JKS", keystoreStream, keyStorePassword);
			_signatureHelper.setKeyAliasAndPassword(keyAlias, keyPassword);
		}
	}


	@Override
	public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException 
	{
		_logger.trace("handle() called");
		_logger.info("  target: {}", target);
		_logger.info("  baseRequest: {}", baseRequest.getContextPath());
		_logger.info("  queryString: {}", baseRequest.getQueryString());
		try
		{
			if ("/metadata".equals(target))
			{
				handleMetadata(response);
			}
			else if ("/websso".equals(target))
			{
				handleWebSSO(request, response);
			}
			else
			{
				_logger.error("Unknown target requested: {}", target);
			}

			baseRequest.setHandled(true);
		} 
		catch (SAMLFailException e) 
		{
			throw new ServletException(e);
		}
		finally{}
	}


	private void handleMetadata(HttpServletResponse response) throws IOException
	{
		_logger.info("Providing metadata for {}", _entityId);

		String entityId = _entityId;	// ${entity.id}
		String serverId = entityId;	// ${server.id}
		String wantAuthnRequestsSigned = Boolean.toString(_responseContextProvider.getWantsAssertionsSigned());
		String signingCertificate = getPEMEncodedCertificate();	// ${certificate.signing}
		String urlSSOService = _serverBase + "/websso"; // ${ssoservice.url}

		String metadata =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
						"<!-- " +
						"   Unsigned metadata for AsimbaSimpleIDP mock IDP "+
						"	Part of AsimbaSSO Baseline distribution "+
						"--> "+
						"<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"${server.id}\" entityID=\"${entity.id}\"> " +
						"  <md:IDPSSODescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" WantAuthnRequestsSigned=\"${wantAuthnRequestsSigned}\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"> " +
						"    <md:KeyDescriptor use=\"signing\"> " +
						"      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"> " +
						"        <ds:X509Data> " +
						"          <ds:X509Certificate>${certificate.signing}</ds:X509Certificate> " +
						"        </ds:X509Data> " +
						"      </ds:KeyInfo> " +
						"    </md:KeyDescriptor> " +
						"    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat> " +
						"    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat> " +
						"    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat> " +
						"    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat> " +
						"    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"${ssoservice.url}\"/> " +
						"  </md:IDPSSODescriptor> " +
						"  <md:Organization xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"> " +
						"    <md:OrganizationName xml:lang=\"en\">asimba.org</md:OrganizationName> " +
						"    <md:OrganizationDisplayName xml:lang=\"\">Asimba SSO IntegrationTest</md:OrganizationDisplayName> " +
						"    <md:OrganizationURL xml:lang=\"en\">http://www.asimba.org</md:OrganizationURL> " +
						"  </md:Organization> " +
						"  <md:ContactPerson xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" contactType=\"administrative\"> " +
						"    <md:Company>Asimba</md:Company> " +
						"    <md:EmailAddress>info@asimba.org</md:EmailAddress> " +
						"    <md:TelephoneNumber>0800-ASIMBA;)</md:TelephoneNumber> " +
						"  </md:ContactPerson> " +
						"</md:EntityDescriptor>";

		// Replacing placeholders:
		metadata = metadata.replace("${server.id}", serverId)
				.replace("${entity.id}", entityId)
				.replace("${wantAuthnRequestsSigned}", wantAuthnRequestsSigned)
				.replace("${certificate.signing}", signingCertificate)
				.replace("${ssoservice.url}", urlSSOService);

		_logger.debug("Providig metadata\n{}", metadata);

		response.getWriter().print(metadata);
	}


	public String getPEMEncodedCertificate()
	{
		return _signatureHelper.getPEMEncodedCertificateFromKeystore();
	}


	private void handleWebSSO(HttpServletRequest request, HttpServletResponse response) throws IOException, SAMLFailException
	{
		if (! request.getParameterMap().containsKey("SAMLRequest")) {
			throw new SAMLFailException("Did not receive inbound 'SAMLRequest' parameter");
		}

		// decode incoming message
		AuthnRequest authnRequest = AuthnRequest.loadAuthnRequest(request.getParameter("SAMLRequest"));

		if (authnRequest == null) {
			throw new SAMLFailException("Could not establish SAMLRequest from 'SAMLRequest' parameter");
		}
		
		try {
			String xml = XMLUtils.getStringFromDocument(authnRequest.getAuthnRequestDocument());
			_logger.info("Received inbound SAML:\n{}", xml);
		} catch (OAException e) {
			_logger.error("Error printing XML", e);
		}

		// create response message context
		Response samlResponse = Response.respondToAuthnRequest(_entityId, authnRequest);

		// Set ID and attributes
		String format = authnRequest.getNameIDPolicy();
		if (org.apache.commons.lang3.StringUtils.isEmpty(format)) {
			format = IUserInfoProvider.SAML_NAMEIDFORMAT_UNSPECIFIED;
			_logger.debug("Using default NameID Policy: {}", format);
		}
		Assertion assertion = samlResponse.getAssertion();
		assertion.setSubjectNameIdFormat(format);
		assertion.setSubjectNameId(_userInfoProvider.getUserId(format));
		assertion.setAttributes(_userInfoProvider.getAttributes());

		// send response message (auto-post to acs-url@idp)
		String builtXml = null;
		String generatedXml = null;
		try {
			// Generate the DOM document from Response-context, and reuse that
			builtXml = samlResponse.getResponse(SAMLMessage.plain);
			samlResponse.loadResponse(builtXml);

			// Consider if and how signing should be applied
			if (_responseContextProvider.getSignAssertion() || 
					_responseContextProvider.getSignResponse()) 
			{
				// First check whether to sign assertion
				if (_responseContextProvider.getSignAssertion()) {
					generatedXml = samlResponse.getMessageWithSignedAssertion(_signatureHelper);
					samlResponse.loadResponse(generatedXml);
				}
				
				// .. because the Response possibly also signs the Assertion signature
				if (_responseContextProvider.getSignResponse()) {
					generatedXml = samlResponse.getSignedMessage(_signatureHelper);
					samlResponse.loadResponse(generatedXml);
				}

			} else {
				generatedXml = XMLUtils.getStringFromDocument(samlResponse.getResponseDocument());	
			}
			
			_logger.info("Sending outbound SAML to {}:\n{}", 
					samlResponse.getDestination(), generatedXml);
		} catch (OAException | XMLStreamException e) {
			_logger.error("Error printing XML", e);
		}
		
		try {
			sendAutoSubmitFormPage(response, samlResponse.getDestination(), generatedXml);
		} catch (XMLStreamException e) {
			throw new SAMLFailException("Could not send SAML Response: "+e.getMessage());
		}

		_logger.info("Sent auto post HTML form with SAML Response");
	}


	private void sendAutoSubmitFormPage(HttpServletResponse response, 
			String target, String responseMessage) throws IOException, XMLStreamException
	{
		String autoSubmitPage = "<!DOCTYPE html>" +
				"<HTML>" +
				" <HEAD> " +
				" <META charset=\"UTF-8\"> " +
				" </HEAD> " +
				" <BODY onload=\"document.forms[0].submit()\"> " +
				" <FORM method=\"POST\" action=\"${form.target}\"> " +
				" <INPUT type=\"hidden\" name=\"SAMLResponse\" value=\"${saml.response}\" /> " +
				" </FORM> " +
				" </BODY> " +
				" </HTML>";
		
		// Replacing placeholders:
		byte [] encoded = Base64.encodeBase64(responseMessage.getBytes("UTF-8"), false);	// false=not chunked
		String encodedResponseMessage = new String(encoded, Charset.forName("UTF-8"));
		
		autoSubmitPage = autoSubmitPage.replace("${form.target}", target)
				.replace("${saml.response}", encodedResponseMessage);
		
		// Set Response Content Type:
		response.setContentType("text/html; charset=utf-8");
		
		response.getWriter().print(autoSubmitPage);
		response.getWriter().flush();
		return;

	}


}
