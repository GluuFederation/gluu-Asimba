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
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

/**
 * Tests the sending of different SAML2 AuthnRequest messages with specific properties, 
 * both valid as well as invalid.<br/>
 * <br/>
 * Binding properties: all SAML messages are sent through HTTP-Redirect binding, and 
 * the responses are received through HTTP-Post binding.<br/>
 * <br/>
 * Tests being performed in this class:
 * <ul>
 * <li>UnsignedRequest : tests whether unsigned requests are rejected correctly</li>
 * </ul>
 *  
 * @author mdobrinic
 *
 */
public class CustomAuthnRequestIntegrationTest {
	private static Logger _logger = LoggerFactory.getLogger(CustomAuthnRequestIntegrationTest.class);
	
	private WebClient _webClient;
	private String _samlWebSSOUrl;
	private SAML2SP _samlClient;

	
	@Before
	public void setup() throws Exception
	{
		_webClient = new WebClient();
		_samlWebSSOUrl = RunConfiguration.getInstance().getProperty("asimbawa.saml.websso.url");
		_samlClient = new SAML2SP("urn:asimba:requestor:samlclient-test:customauthnreq", null);	// no SSL context (yet...)
		_samlClient.registerInRequestorPool("requestorpool.1");
	}
	
	@After
	public void stop()
	{
		_samlClient.unregister();
		_webClient.closeAllWindows();
	}

	
	@Test @Category(SAMLTests.class)
	public void testUnsignedRequest() throws Exception
	{
		_logger.trace("testUnsignedRequest entered");
		
		// Send unsigned request, when signing is not required
		WebRequest authnRequest = _samlClient.getAuthnWebRequest(_samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		
		_logger.info("Sending request to {}", authnRequest.getUrl().toString());
		
		HtmlPage htmlPage = _webClient.getPage(authnRequest);
		String content = htmlPage.asXml();
		_logger.info("Received (1): {}", content);

		// Assert that we got a HTTP 200/OK:
		assertEquals(200, htmlPage.getWebResponse().getStatusCode());
		
		// Assert that we get the selection-form here:
		HtmlForm form = htmlPage.getFormByName("select");
		assertNotNull(form);
		
		// Just cancel the request:
		HtmlSubmitInput button = form.getInputByName("cancel");
		TextPage textPage = button.click();
		
		// .. and assert that we received AuthnFailed as SubStatuscode as SAML SP: and OK as content:
		String samlSubStatusCode = _samlClient.getReceivedResponse().getSubStatusCode();
		assertEquals("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", samlSubStatusCode);
		assertEquals("OK", textPage.getContent());

		
		// Now override property so signing is required:
		_samlClient.unregisterProperty("saml2.signing");
		_samlClient.registerProperty("saml2.signing", "true");
		
		// Send unsigned request, when signing *is* required
		authnRequest = _samlClient.getAuthnWebRequest(_samlWebSSOUrl, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		
		_logger.info("Sending request to {}", authnRequest.getUrl().toString());
		
		// Prepare for error:
		_webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		
		// and make call
		htmlPage = _webClient.getPage(authnRequest);
		content = htmlPage.asXml();
		_logger.info("Received (B1): {}", content);

		// Assert that we get a HTTP 403/Forbidden response
		assertEquals(403, htmlPage.getWebResponse().getStatusCode());
	}
	
	
	
}
