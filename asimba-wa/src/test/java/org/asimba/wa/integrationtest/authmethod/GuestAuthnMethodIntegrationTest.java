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
package org.asimba.wa.integrationtest.authmethod;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Map;

import org.asimba.wa.integrationtest.RunConfiguration;
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
import com.gargoylesoftware.htmlunit.html.HtmlPage;

/**
 * Tests the configured Guest Authentication Method<br/>
 * This method always returns the configured guest-user's identity<br/>
 * <br/>
 * Uses a SAML2 client to request the authenticated user.<br/>
 * The SAML2 client is dynamically established, and inserted in the requestor-database
 * on the fly<br/>
 * The SAML2 client also starts up a servlet that serves up the metadata containing the
 * ACS-URL that asimba-wa should use to return the Response to<br/>
 * <br/>
 * Note: SAML2 AuthnRequest specific features (XML Signatures, Requesting NameIDFormat, etc)
 * are part of the SAML2 tests.
 *   
 * @author mdobrinic
 *
 */
public class GuestAuthnMethodIntegrationTest {
	private static Logger _logger = LoggerFactory.getLogger(GuestAuthnMethodIntegrationTest.class);

	private WebClient _webClient;
	private String _samlWebSSOUrl;
	private SAML2SP _samlClient;
	
	@Before
	public void setup() throws Exception
	{
		_webClient = new WebClient();
		_samlWebSSOUrl = RunConfiguration.getInstance().getProperty("asimbawa.saml.websso.url");
		_samlClient = new SAML2SP("urn:asimba:requestor:samlclient-test", null);	// no SSL context (yet...)
		_samlClient.registerInRequestorPool("requestorpool.1");
	}
	
	@After
	public void stop()
	{
		_samlClient.unregister();
		_webClient.closeAllWindows();
	}
	
	
	@Test @Category(AuthnMethodTests.class)
	public void guestSuccessTest() throws Exception
	{
		_logger.trace("guestSuccessTest entered.");
		
		// Make the AuthnRequest
		String content;
		WebRequest webRequest = _samlClient.getAuthnWebRequest(_samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		_logger.info("Sending (httpclient) request to {}", webRequest.getUrl().toString());
		
		HtmlPage htmlPage = _webClient.getPage(webRequest);
		content = htmlPage.asXml();
		_logger.info("Received (1): {}", content);
		
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
		
		// Now make assertions from the received SAMLResponse
		Response samlResponse = _samlClient.getReceivedResponse();
		assertNotNull(samlResponse);
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success", samlResponse.getStatusCode());
		
		_logger.info("NameID:{}", samlResponse.getAssertion().getSubjectNameId());
		_logger.info("NameIDFormat:{}", samlResponse.getAssertion().getSubjectNameIdFormat());
		
		Map<String, String> attributes = samlResponse.getAssertion().getParsedAttributes();
		_logger.info("Attributes received: {}", attributes);
		
		// Do some assertions on the attributes (guest-user related)
		assertEquals("no@email.com", attributes.get("email"));
		assertEquals("Guest", attributes.get("firstname"));
		assertNull(attributes.get("phonenr"));
	}
	
	
	@Test
	public void testThousand() throws Exception
	{
		final int ATTEMPTS = 1000;
		
		int attemptsLeft = ATTEMPTS;
		
		long start = System.currentTimeMillis();
		
		while (attemptsLeft > 0) 
		{
			_logger.info("Attempts left: {}", attemptsLeft);
			_webClient.getCookieManager().clearCookies();
			
			// Make the AuthnRequest
			String content;
			WebRequest webRequest = _samlClient.getAuthnWebRequest(_samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			
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
			
		
		long end = System.currentTimeMillis();
		
		_logger.info("Time run for {} attempts in seconds: {}s", ATTEMPTS, ((end - start)/1000) );
		

	}
	
}
