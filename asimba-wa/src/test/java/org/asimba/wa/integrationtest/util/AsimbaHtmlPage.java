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
package org.asimba.wa.integrationtest.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

/**
 * Helper class to work with getting specific contents from a returned HTML Page
 * 
 * @author mdobrinic
 *
 */
public class AsimbaHtmlPage {
	/** Local logger instance */
	private static Logger _logger = LoggerFactory.getLogger(AsimbaHtmlPage.class);


	private HtmlPage _htmlPage;

	public AsimbaHtmlPage(HtmlPage htmlPage)
	{
		init(htmlPage);
	}

	public void init(HtmlPage htmlPage)
	{
		_htmlPage = htmlPage;
	}

	/**
	 * Find a link (anchor element) that has "{parameter}={parameterValue}" in its querystring
	 * @param paramName
	 * @param paramValue
	 * @return HtmlAnchor that matches, or null if there was no match
	 */
	public HtmlAnchor findLinkWithParameterValue(String paramName, String paramValue)
	{
		if (_htmlPage == null) {
			_logger.error("Uninitialized htmlPage"); 
			return null;
		}
		HtmlAnchor theAnchor = null;
		// alternative to:
		//	List<?> list = htmlPage.getByXPath(
		//		"/html/body/div[@id='container']/div[@id='content']/div[@id='contentMain']/form[@id='selectionForm']/fieldset/ul/li/a");

		try {
			List<HtmlAnchor> anchors = _htmlPage.getAnchors();
			theanchorloop:
				for(HtmlAnchor anchor: anchors) {
					String href = anchor.getHrefAttribute();
					List<NameValuePair> params = URLEncodedUtils.parse(new URI(href), "UTF-8");
					for(NameValuePair nvp: params) 
					{
						if (paramName.equals(nvp.getName()))
						{
							if (paramValue.equals(nvp.getValue()))
							{
								theAnchor = anchor;
								break theanchorloop;
							}
						}
					}
				}
		}
		catch (URISyntaxException e) {
			_logger.error("Could not encode parameter", e);
			return null;
		}

		_logger.info("Found anchor: {}", theAnchor);
		return theAnchor;
	}
}
