/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2015 Asimba
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
package org.asimba.wa.integrationtest.clustered;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Map;

import org.asimba.wa.integrationtest.RunConfiguration;
import org.asimba.wa.integrationtest.authmethod.AuthnMethodTests;
import org.asimba.wa.integrationtest.saml.RemoteSAMLIntegrationTest;
import org.asimba.wa.integrationtest.saml.SAMLTests;
import org.asimba.wa.integrationtest.saml2.idp.BasicResponseContextProvider;
import org.asimba.wa.integrationtest.saml2.idp.BasicUserInfoProvider;
import org.asimba.wa.integrationtest.saml2.idp.IResponseContextProvider;
import org.asimba.wa.integrationtest.saml2.idp.IUserInfoProvider;
import org.asimba.wa.integrationtest.saml2.idp.SAML2IDP;
import org.asimba.wa.integrationtest.saml2.model.Response;
import org.asimba.wa.integrationtest.saml2.sp.SAML2SP;
import org.asimba.wa.integrationtest.util.AsimbaHtmlPage;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;

/**
 * The clustered tests focus on testing a cluster configuration of 2 Asimba servers. The servers
 * have a clustered managed storage for Sessions, TGTs and Artificats.<br/>
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
 * @author jgouw
 *
 */
public class SamlClusteredIntegrationTest {


	private static Logger _logger = LoggerFactory.getLogger(RemoteSAMLIntegrationTest.class);

	private WebClient _webClient;
	private String _samlSite, _samlDomain0, _samlDomain1;

	@Before
	public void setup()
	{
		_webClient = new WebClient();
		RunConfiguration rc = RunConfiguration.getInstance();		
		_samlSite=rc.getProperty("asimbawa.saml.websso.site");
		_samlDomain0=rc.getProperty("asimbawa.saml.websso.domain0");
		_samlDomain1=rc.getProperty("asimbawa.saml.websso.domain1");
	}

	@After
	public void stop()
	{
		_webClient.closeAllWindows();
	}

	/** 
	 * Verify basic saml flow is handled correctly when SP and IDP communicate with different nodes.<br/>
	 * <ul>
	 * <li>SP sends authentication request to node 1 (port 8081)</li>
	 * <li>IDP communicates with node 0 (port 8080)</li>
	 * <li>SP receives Authentication OK<li>
	 * </ul>
	 */
	@Test @Category(ClusteredTests.class)
	public void testBasicSamlAuthIdpNode0SpNode1() throws Exception
	{
		_logger.trace("testBasicSamlAuthIdpNode0SpNode1 entered.");

		// ===== Setup and configure the Remote SAML IDP
		SAML2IDP saml2IDP = setupMockIdp();

		// ===== Setup and configure a SAML SP as Test Client
		SAML2SP samlClient = setupTestSP();


		// ================================================================
		// Initiate the Authentication flow to node 1
		String samlWebSSOUrl = _samlDomain1+_samlSite;
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

		_logger.trace("testBasicSamlAuthIdpNode0SpNode1 succeeded.");
	}
	
	/** 
	 * Verify a session is handled okay when SP interacts with 2 different nodes:<br/>
	 * <ul>
	 * <li>SP sends authentication request to node 1 (port 8081)</li>
	 * <li>IDP communicates with node 0 (port 8080)</li>
	 * <li>SP receives Authentication OK <li>
	 * </ul>
	 */	@Test @Category(ClusteredTests.class)
	public void testDoubleSignOnDifferentNodes() throws Exception
	{
		_logger.trace("testDoubleSignOnDifferentNodes entered");
		SAML2SP samlClient = setupTestSP();
		String samlWebSSOUrl = _samlDomain1 + _samlSite;
		
		// Now override property so signing is required:
		samlClient.unregisterProperty("saml2.signing");
		samlClient.registerProperty("saml2.signing", "true");

		// Send unsigned request, when signing is required to node 1
		WebRequest authnRequest = samlClient.getAuthnWebRequest(samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		_logger.info("Sending request to {}", authnRequest.getUrl().toString());

		// Prepare for error and send page
		_webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		HtmlPage htmlPage = _webClient.getPage(authnRequest);
		String content = htmlPage.asXml();
		_logger.info("Received (1): {}", content);

		// Assert that we get a HTTP 403/Forbidden response
		assertEquals(403, htmlPage.getWebResponse().getStatusCode());
		
		// Now override property so signing is no longer required:
		samlClient.unregisterProperty("saml2.signing");
		samlClient.registerProperty("saml2.signing", "false");
		
		// send request to other node
		samlWebSSOUrl = _samlDomain0 + _samlSite;
		
		// Send unsigned request, when signing is NOT required to node 0
		authnRequest = samlClient.getAuthnWebRequest(samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);		
		_logger.info("Sending request to {}", authnRequest.getUrl().toString());
		
		htmlPage = _webClient.getPage(authnRequest);
		content = htmlPage.asXml();
		_logger.info("Received (B1): {}", content);

		// Assert that we got a HTTP 200/OK:
		assertEquals(200, htmlPage.getWebResponse().getStatusCode());

		// Assert that we get the selection-form here:
		HtmlForm form = htmlPage.getFormByName("select");
		assertNotNull(form);
		
		// Just cancel the request:
		HtmlSubmitInput button = form.getInputByName("cancel");
		TextPage textPage = button.click();
		
		// .. and assert that we received AuthnFailed as SubStatuscode as SAML SP: and OK as content:
		String samlSubStatusCode = samlClient.getReceivedResponse().getSubStatusCode();
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", samlSubStatusCode);
		assertEquals("OK", textPage.getContent());

		_logger.trace("testDoubleSignOnDifferentNodes succeeded");		
	}

	/**
	 * Verify basic saml flow is handled correctly when SP starts on one node and sends confirmation to 
	 * another node.<br/>
	 * <ul>
	 * <li>SP sends authentication request to node 1(port 8081)</li>
	 * <li>Logon window is shown by IDP</li>
	 * <li>SP sends confirmation to node 0 (port 8080)</LI>
	 * <li>
	 * </ul>
	 */
	@Test @Category(ClusteredTests.class)
	public void testSPInteracting2Nodes() throws Exception
	{
		_logger.trace("testSPInteracting2Nodes entered");	
		SAML2SP samlClient = setupTestSP();
		SAML2IDP saml2IDP = setupMockIdp();
		String samlWebSSOUrl = _samlDomain1 + _samlSite;

		_webClient.getCookieManager().clearCookies();

		// Make the AuthnRequest
		String content;
		WebRequest webRequest = samlClient.getAuthnWebRequest(samlWebSSOUrl,
				SAMLConstants.SAML2_REDIRECT_BINDING_URI);

		HtmlPage htmlPage = _webClient.getPage(webRequest);
		content = htmlPage.asXml();

		// Make assertions about the response:
		// -- one of the items has a link that has "profile=local.guest" in
		// querystring
		AsimbaHtmlPage asimbaHtmlPage = new AsimbaHtmlPage(htmlPage);

		// Make assertions about the response:
		// -- one of the items has a link that has "profile=remote.saml" in
		// querystring
		HtmlAnchor theAnchor = asimbaHtmlPage.findLinkWithParameterValue(
				"profile", "local.guest");
		assertNotNull(theAnchor);

		// change the node of the reply to node 0
		String attrLink = theAnchor.getAttribute("href");
		attrLink = _samlDomain0 + attrLink;
		theAnchor.setAttribute("href", attrLink);
		
		// Select a link by "clicking" on it; should result in the redirect to
		// the SAMLSP Servlet:
		TextPage textPage = theAnchor.click();

		content = textPage.getContent();
		_logger.info("Received (2): {}", content); // expect: "OK"
		assertEquals("OK", content);

		// ===== Clean up
		samlClient.unregister();
		saml2IDP.unregister();

		_logger.trace("testSPInteracting2Nodes succeeded");
	}

	/**
	 * Verify no faults occur when handling 1000 successfull authentications.<br/>
	 * Verify timer expiration cleans up things correctly.<br/>
	 * For this a basic flow is used:
	 * <ul>
	 * <li>SP sends authentication request to node 1 (port 8081)</li>
	 * <li>Logon window is shown by IDP</li>
	 * <li>SP sends confirmation to node 0 (port 8080)</LI>
	 * <li>
	 * </ul>
	 */
	@Test @Category(ClusteredTests.class)
	public void testClusteredThousand() throws Exception
	{
		_logger.trace("testClusteredThousand entered");	
		final int ATTEMPTS = 1000;		
		int attemptsLeft = ATTEMPTS;		
		long start = System.currentTimeMillis();
				
		SAML2SP samlClient = setupTestSP();
		SAML2IDP saml2IDP = setupMockIdp();
		String samlWebSSOUrl = _samlDomain1 + _samlSite;

		while (attemptsLeft > 0) 
		{
			_logger.info("Attempts left: {}", attemptsLeft);
						
			_webClient.getCookieManager().clearCookies();
			
			// Make the AuthnRequest
			String content;
			WebRequest webRequest = samlClient.getAuthnWebRequest(samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			
			HtmlPage htmlPage = _webClient.getPage(webRequest);
			content = htmlPage.asXml();
			
			// Make assertions about the response:
			// -- one of the items has a link that has "profile=local.guest" in querystring
			AsimbaHtmlPage asimbaHtmlPage = new AsimbaHtmlPage(htmlPage);
			
			// Make assertions about the response:
			// -- one of the items has a link that has "profile=remote.saml" in querystring
			HtmlAnchor theAnchor = asimbaHtmlPage.findLinkWithParameterValue("profile", "local.guest");
			assertNotNull(theAnchor);

			// Select a link by "clicking" on it; should result in the redirect to the SAMLSP Servlet:
			TextPage textPage = theAnchor.click();
			
			content = textPage.getContent();
			_logger.info("Received (2): {}", content);	// expect: "OK"
			assertEquals("OK", content);			
			attemptsLeft --;
		}			
		
		// ===== Clean up
		samlClient.unregister();
		saml2IDP.unregister();

		long end = System.currentTimeMillis();
		
		_logger.info("Time run for {} attempts in seconds: {}s", ATTEMPTS, ((end - start)/1000) );
		_logger.trace("testClusteredThousand succeeded");
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
	
}
