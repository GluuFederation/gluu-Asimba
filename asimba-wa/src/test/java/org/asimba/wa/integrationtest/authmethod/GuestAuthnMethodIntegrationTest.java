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

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.asimba.wa.integrationtest.client.saml.Response;
import org.asimba.wa.integrationtest.client.saml.SAMLClient;
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

	private static final String ASIMBAWA_SAML_WEBSSO_REDIRECT_URI = 
			"http://localhost:8080/asimba-wa/profiles/saml2/sso/web";
	
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
	
	
	@Test @Category(AuthnMethodTests.class)
	public void guestSuccessTest() throws Exception
	{
		_logger.trace("guestSuccessTest entered.");
		
		// Setup the SAML Client with asimba-wa
		SAMLClient samlClient = new SAMLClient("urn:asimba:requestor:samlclient-test", null);	// no SSL context (yet...)
		samlClient.registerInRequestorPool("requestorpool.1");
	
		// Make the AuthnRequest
		String content;
		WebRequest webRequest = samlClient.getAuthnWebRequest(ASIMBAWA_SAML_WEBSSO_REDIRECT_URI, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		_logger.info("Sending (httpclient) request to {}", webRequest.getUrl().toString());
		
		HtmlPage htmlPage = _webClient.getPage(webRequest);
		content = htmlPage.asXml();
		_logger.info("Received (1): {}", content);
		
		// Make assertions about the response:
		// -- one of the items has a link that has "profile=local.guest" in querystring
		HtmlAnchor theAnchor = null;
		// alternative to:
		//	List<?> list = htmlPage.getByXPath(
		//		"/html/body/div[@id='container']/div[@id='content']/div[@id='contentMain']/form[@id='selectionForm']/fieldset/ul/li/a");
		List<HtmlAnchor> anchors = htmlPage.getAnchors();
		theanchorloop:
		for(HtmlAnchor anchor: anchors) {
			String href = anchor.getHrefAttribute();
			List<NameValuePair> params = URLEncodedUtils.parse(new URI(href), "UTF-8");
			for(NameValuePair nvp: params) 
			{
				if ("profile".equals(nvp.getName()))
				{
					if ("local.guest".equals(nvp.getValue()))
					{
						theAnchor = anchor;
						break theanchorloop;
					}
				}
			}
		}
		
		_logger.info("Found anchor: {}", theAnchor);
		assertNotNull(theAnchor);

		// Select a link by "clicking" on it; should result in the redirect to the SAMLSP Servlet:
		TextPage textPage = theAnchor.click();
		
		content = textPage.getContent();
		_logger.info("Received (2): {}", content);	// expect: "OK"
		
		// Now make assertions from the received SAMLResponse
		Response samlResponse = samlClient.getReceivedResponse();
		assertNotNull(samlResponse);
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success", samlResponse.getStatusCode());
		
		_logger.info("NameID:{}", samlResponse.getSubjectNameId());
		_logger.info("NameIDFormat:{}", samlResponse.getSubjectNameIdFormat());
		
		Map<String, String> attributes = samlResponse.getAttributes();
		_logger.info("Attributes received: {}", attributes);
		
		// Do some assertions on the attributes (guest-user related)
		assertEquals("no@email.com", attributes.get("email"));
		assertEquals("Guest", attributes.get("firstname"));
		assertNull(attributes.get("phonenr"));
	}
}
