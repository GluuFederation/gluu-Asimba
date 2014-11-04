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
package org.asimba.wa.integrationtest.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.asimba.wa.integrationtest.RunConfiguration;
import org.asimba.wa.integrationtest.saml2.idp.BasicResponseContextProvider;
import org.asimba.wa.integrationtest.saml2.idp.BasicUserInfoProvider;
import org.asimba.wa.integrationtest.saml2.idp.IResponseContextProvider;
import org.asimba.wa.integrationtest.saml2.idp.IUserInfoProvider;
import org.asimba.wa.integrationtest.saml2.idp.SAML2IDP;
import org.asimba.wa.integrationtest.saml2.model.AuthnRequest;
import org.asimba.wa.integrationtest.saml2.model.Response;
import org.asimba.wa.integrationtest.saml2.sp.SAML2SP;
import org.asimba.wa.integrationtest.util.AsimbaHtmlPage;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

/**
 * The Remote SAML Integration Test performs testing of the Remote SAML authentication method, where
 * Asimba is fulfilling the role of a SAML Proxy. While this involves an extra (SAML) IDP, this 
 * integration test will actually setup a full mock SAML2 IDP service to involve in the tests.<br/>
 * <br/>
 * The Mock SAML2 IDP is implemented as a servlet, provides metadata, can sign assertions, all limited
 * to a minimal set of features though, but they are able to trigger certain exectution flows inside 
 * Asimba.<br/>
 * <br/>
 * In general, a test is required to:<br/>
 * <ul>
 * <li>Instantiate a new SAML2 IDP servlet</li>
 * <li>Configure that SAML2 IDP servlet to respond in a particular way</li>
 * <li>Register the SAML2 IDP as a SAML IDP with Asimba</li>
 * <li>Setup a SAML2 SP to be able to send SAML AuthnRequest's to Asimba</li>
 * <li>Initiate the flow and make assertions about the behavior</li>
 * </ul>
 * The purpose is to eliminate each and every external dependency outside the build system.
 * 
 * @author mdobrinic
 *
 */
public class RemoteSAMLIntegrationTest {


	private static Logger _logger = LoggerFactory.getLogger(RemoteSAMLIntegrationTest.class);

	private WebClient _webClient;


	@Before
	public void setup()
	{
		_webClient = new WebClient();
	}

	@After
	public void stop()
	{
		_webClient.closeAllWindows();
	}

	@Test
	public void testSAMLIDPSetup() throws Exception
	{
		_logger.trace("testSAMLIDPSetup entered.");
		SAML2IDP saml2IDP = setupMockIdp();


		saml2IDP.unregister();

		_logger.trace("testSAMLIDPSetup succeeded.");
	}


	@Test
	public void testDeflateInflate() throws Exception
	{
		String acsUrl = "http://acs/url";
		String entityId = "entity:id";
		AuthnRequest authnRequest = new AuthnRequest(acsUrl, entityId);
		String authnRequestMessage = authnRequest.getRequest(AuthnRequest.plain);
		_logger.info("Message to send (plain):\n{}", authnRequestMessage);

		authnRequestMessage = authnRequest.getRequest(AuthnRequest.base64);
		_logger.info("Message to send (encoded):\n{}", authnRequestMessage);

		// Decoding:
		authnRequest = AuthnRequest.loadAuthnRequest(authnRequestMessage);

		_logger.info("Message received (decoded):\n{}", authnRequestMessage);

		// Parsing:
		_logger.debug("AuthnRequest Issuer: {}", authnRequest.getIssuer());
		assertEquals(entityId, authnRequest.getIssuer());

		_logger.debug("NameIDPolicy : {}", authnRequest.getNameIDPolicy());
		_logger.debug("ID: {}", authnRequest.getId());
		_logger.debug("ProtocolBinding : {}", authnRequest.getProtocolBinding());
		_logger.debug("Assertion Consumer URL: {}", authnRequest.getACSURL());
	}


	@Test
	public void testBasicRemoteSAMLAuthentication() throws Exception
	{
		_logger.trace("testBasicRemoteSAMLAuthentication entered.");

		// ===== Setup and configure the Remote SAML IDP
		SAML2IDP saml2IDP = setupMockIdp();

		// ===== Setup and configure a SAML SP as Test Client
		SAML2SP samlClient = setupTestSP();


		// ================================================================
		// Initiate the Authentication flow
		String samlWebSSOUrl = RunConfiguration.getInstance().getProperty("asimbawa.saml.websso.url");
		String content;
		WebRequest webRequest = samlClient.getAuthnWebRequest(samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		_logger.info("Sending (httpclient) request to {}", webRequest.getUrl().toString());

		HtmlPage htmlPage = _webClient.getPage(webRequest);
		// content = htmlPage.asXml();
		// _logger.info("Received (1): {}", content);

		AsimbaHtmlPage asimbaHtmlPage = new AsimbaHtmlPage(htmlPage);

		// Make assertions about the response:
		// -- one of the items has a link that has "profile=remote.saml" in querystring
		HtmlAnchor theAnchor = asimbaHtmlPage.findLinkWithParameterValue("profile", "remote.saml");
		assertNotNull(theAnchor);

		// Select a link by "clicking" on it; should result in the redirect to the SAMLSP Servlet:
		TextPage textPage = theAnchor.click();
		content = textPage.getContent();

		_logger.info("Received (2): {}", content);	// expect: "OK"
		assertEquals("OK", content);


		// ================================================================
		// ===== Clean up
		samlClient.unregister();
		saml2IDP.unregister();

		_logger.trace("testBasicRemoteSAMLAuthentication succeeded.");

	}

	private SAML2SP setupTestSP() throws Exception {
		SAML2SP samlClient;

		// Setup the SAML Client with asimba-wa
		samlClient = new SAML2SP("urn:asimba:requestor:samlclient-test", null);	// no SSL context (yet...)
		samlClient.registerInRequestorPool("requestorpool.1");
		return samlClient;
	}

	private SAML2IDP setupMockIdp() throws Exception {
		RunConfiguration rc = RunConfiguration.getInstance();

		String idpEntityId = rc.getProperty("asimbawa.saml.idp.entityId");
		IUserInfoProvider userInfoProvider = new BasicUserInfoProvider();
		IResponseContextProvider responseContextProvider = new BasicResponseContextProvider();
		
		SAML2IDP saml2IDP = new SAML2IDP(idpEntityId, null, userInfoProvider, responseContextProvider);

		String keystoreFilename = rc.getProperty("asimbawa.saml.keystore", "asimba-test-keystore.jks");
		String keystorePassword = rc.getProperty("asimbawa.saml.keystore.password", "changeit");
		String keyAlias = rc.getProperty("asimbawa.saml.idp.keyalias", "asimba-test-idp");
		String keyPassword = rc.getProperty("asimbawa.saml.idp.keypassword", "changeit");
		saml2IDP.setKeysAndCertificates(keystoreFilename, keyPassword, keyAlias, keystorePassword);

		saml2IDP.registerWithAsimba();
		return saml2IDP;
	}


	@Test
	public void doThousandAuthentications() throws Exception
	{
		_logger.trace("doThousandAuthentications() entered");
		// ===== Setup and configure the Remote SAML IDP
		SAML2IDP saml2IDP = setupMockIdp();

		// ===== Setup and configure a SAML SP as Test Client
		SAML2SP samlClient = setupTestSP();


		// ================================================================
		// Initiate the Authentication flow
		String samlWebSSOUrl = RunConfiguration.getInstance().getProperty("asimbawa.saml.websso.url");
		String content;
		WebRequest webRequest = null;
		
		final int ATTEMPTS = 1000;
		
		int authnsLeft = ATTEMPTS;
		
		long startTime = System.currentTimeMillis();
		
		while (authnsLeft > 0) {
			_logger.info("Attempt {}", (ATTEMPTS - authnsLeft + 1));
			webRequest = samlClient.getAuthnWebRequest(samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			_logger.info("Sending (httpclient) request to {}", webRequest.getUrl().toString());
			
			HtmlPage htmlPage = _webClient.getPage(webRequest);
			AsimbaHtmlPage asimbaHtmlPage = new AsimbaHtmlPage(htmlPage);

			HtmlAnchor theAnchor = asimbaHtmlPage.findLinkWithParameterValue("profile", "remote.saml");
			assertNotNull(theAnchor);

			// Select a link by "clicking" on it; should result in the redirect to the SAMLSP Servlet:
			TextPage textPage = theAnchor.click();
			content = textPage.getContent();

			// Make assertions about the response:
			// _logger.info("Received (2): {}", content);	// expect: "OK"
			assertEquals("OK", content);
			
			// Clear cookiejar
			_webClient.getCookieManager().clearCookies();
			
			authnsLeft--;
		}
		
		long endTime = System.currentTimeMillis();
		
		_logger.info("Time run for {} attempts in seconds: {}s", ATTEMPTS, ((endTime - startTime)/1000) );
		

		// ================================================================
		// ===== Clean up
		samlClient.unregister();
		saml2IDP.unregister();
		
		_logger.trace("doThousandAuthentications() succeeded");
	}


	public void testResponse() throws Exception
	{
		Response response;

		response = new Response();

	}
}
