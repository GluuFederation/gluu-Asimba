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

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.asimba.wa.integrationtest.RunConfiguration;
import org.asimba.wa.integrationtest.saml2.model.Response;
import org.asimba.wa.integrationtest.saml2.sp.SAML2SP;
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
 * Testing the Identifying method executes two flows:<br/>
 * <ul>
 * <li>Navigating to the identifying profile, and entering a valid user_id (asimba1)</li>
 * <li>Navigating to the identifying profile, and entering an invalid user_id (asimba-invalid)</li>
 * </ul>
 * It does so by making a request to the SAML2 IDP Profile
 * 
 * @author mdobrinic
 */
public class IdentifyingAuthnMethodIntegrationTest {

	private static Logger _logger = LoggerFactory.getLogger(IdentifyingAuthnMethodIntegrationTest.class);

	private WebClient _webClient;
	private String _samlWebSSOUrl;
	private SAML2SP _samlClient;

	@Before
	public void setup() throws Exception
	{
		_webClient = new WebClient();
		_samlWebSSOUrl = RunConfiguration.getInstance().getProperty("asimbawa.saml.websso.url");
		_samlClient = new SAML2SP("urn:asimba:requestor:samlclient-test:identifying", null);	// no SSL context (yet...)
		_samlClient.registerInRequestorPool("requestorpool.1");
	}

	@After
	public void stop()
	{
		_samlClient.unregister();
		_webClient.closeAllWindows();
	}


	@Test @Category(AuthnMethodTests.class)
	public void testKnownUser() throws Exception
	{
		_logger.trace("testKnownUser entered");

		HtmlPage htmlPage = navigateToIdentifyingForm(_samlClient, _webClient);
		String knownUser = RunConfiguration.getInstance().getProperty("identifying.user.known");

		HtmlForm form = htmlPage.getFormByName("login");
		HtmlTextInput userIdInput = form.getInputByName("user_id");
		HtmlSubmitInput button = form.getInputByName("login");

		userIdInput.setValueAttribute(knownUser);

		TextPage textPage = button.click();
		String content = textPage.getContent();
		_logger.debug("Received (3t): {}", content);	// redirect to ACS; should be OK:
		assertEquals("OK", content);
		
		// Now make assertions from the received SAMLResponse
		Response samlResponse = _samlClient.getReceivedResponse();
		assertNotNull(samlResponse);
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success", samlResponse.getStatusCode());

		Map<String, String> attributes = samlResponse.getAssertion().getParsedAttributes();
		_logger.info("Attributes received: {}", attributes);

		// Do some assertions on the attributes (guest-user related)
		assertEquals("alice@asimba.org", attributes.get("email"));
		assertEquals("Alice", attributes.get("firstname"));


		// Get logged in info?
		
		
		_logger.info("testKnownUser finished OK.");
	}
	
	
	@Test @Category(AuthnMethodTests.class)
	public void testUnknownUser() throws Exception
	{
		_logger.trace("testUnknownUser entered");
		
		HtmlPage htmlPage = navigateToIdentifyingForm(_samlClient, _webClient);

		String unknownUser = RunConfiguration.getInstance().getProperty("identifying.user.unknown");

		HtmlForm form = htmlPage.getFormByName("login");
		HtmlTextInput userIdInput = form.getInputByName("user_id");
		HtmlSubmitInput button = form.getInputByName("login");

		userIdInput.setValueAttribute(unknownUser);

		htmlPage = button.click();
		
		// TextPage textPage = button.click();
		// String content = textPage.getContent();
		String content = htmlPage.asXml();
		_logger.debug("Received (3): {}", content);

		// Now make assertions from the received HTML page
		HtmlAnchor warningAnchor = htmlPage.getAnchorByName("warning.NO_SUCH_USER_FOUND");
		assertNotNull(warningAnchor);

		_logger.info("testUnknownUser finished OK.");
	}


	private HtmlPage navigateToIdentifyingForm(SAML2SP samlClient, WebClient webClient) throws Exception
	{
		// Make the AuthnRequest
		String content;
		WebRequest webRequest = samlClient.getAuthnWebRequest(_samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		_logger.debug("Sending (httpclient) request to {}", webRequest.getUrl().toString());

		HtmlPage htmlPage = _webClient.getPage(webRequest);
		content = htmlPage.asXml();
		_logger.debug("Received (1): {}", content);

		// Make assertions about the response:
		// -- one of the items has a link that has "profile=local.identifying" in querystring
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
						if ("local.identifying".equals(nvp.getValue()))
						{
							theAnchor = anchor;
							break theanchorloop;
						}
					}
				}
			}

		_logger.info("Found anchor: {}", theAnchor);
		assertNotNull(theAnchor);

		// Click the identifying method -- should result in HTML page with form to enter username
		htmlPage = theAnchor.click();

		content = htmlPage.asXml();
		_logger.debug("Received (2): {}", content);
		
		return htmlPage;
	}
}
