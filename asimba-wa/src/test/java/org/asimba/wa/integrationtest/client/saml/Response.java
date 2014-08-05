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

import java.util.HashMap;
import java.util.Map;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.asimba.utility.xml.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.alfaariss.oa.OAException;

public class Response {
	
	private static final Logger _logger = LoggerFactory.getLogger(Response.class);

	/** contains the parsed inbound SAML Response message */
	private Document _responseDocument = null;
	
	/** lazy initialized parsed attributes from the Response */
	transient private Map<String, String> _responseAttributes = null;
	
	public Response()
	{
	}
	
	
	public void loadResponse(String responseString)
	{
		try {
			_responseDocument = XMLUtils.getDocumentFromString(responseString, true);
			_responseAttributes = null;
		} catch (OAException oae) {
			_logger.error("Could not parse SAML Response document: {}", oae.getMessage(), oae);
		}
	}
	
	
	/**
	 * Execute provided XPath query on document. Query must return String-value, otherwise
	 * unexpected behavior occurs
	 * 
	 * @param xpathQuery XPath Query to perform 
	 * @param document Document to perform query on
	 * @return value, or null when error occurred
	 */
	private String executeXPathValueQuery(String xpathQuery, Document document)
	{
		if (document == null) {
			_logger.error("No document specified.");
			return null;
		}
		
		XPath xpath = XPathFactory.newInstance().newXPath();
		xpath.setNamespaceContext(new SimpleSAMLNamespaceContext(null));
		
		try {
			return xpath.compile(xpathQuery).evaluate(_responseDocument);
		} catch (XPathExpressionException e) {
			_logger.error("Exception when processing XPath Query: {}", e.getMessage(), e);
			return null;
		}
	}
	
	/**
	 * Retrieve the value of the StatusCode element
	 * 
	 * @return value, or null when error occurred
	 */
	public String getStatusCode()
	{
		String xpathQuery = "/saml2p:Response/saml2p:Status/saml2p:StatusCode/@Value";
		return executeXPathValueQuery(xpathQuery, _responseDocument);
	}
	
	/**
	 * Retrieve the value of the Subject/NameId element
	 * @return value, or null when error occurred
	 */
	public String getSubjectNameId()
	{
		String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID";
		return executeXPathValueQuery(xpathQuery, _responseDocument);
	}
	
	/**
	 * Retrieve the value of the Subject/NameId@Format attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getSubjectNameIdFormat()
	{
		String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID/@Format";
		return executeXPathValueQuery(xpathQuery, _responseDocument);
	}
	
	
	private void parseAttributes()
	{
		String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:AttributeStatement/saml2:Attribute";
		
		if (_responseDocument == null) {
			_logger.error("No document specified.");
			return;
		}
		
		Map<String, String> attributeMap = new HashMap<>();
		
		XPath xpath = XPathFactory.newInstance().newXPath();
		xpath.setNamespaceContext(new SimpleSAMLNamespaceContext(null));
		
		try {
			NodeList nodes = (NodeList) 
					xpath.compile(xpathQuery).evaluate(_responseDocument, XPathConstants.NODESET);
			if (nodes != null) {
				for (int i = 0; i < nodes.getLength(); i++) {
					// get value of @Name attribute
					Node n = nodes.item(i); 

					String name = n.getAttributes().getNamedItem("Name").getNodeValue();
					
					// get the first AttributeValue childnode
					NodeList valueNodes = n.getChildNodes();
					for (int ci = 0; ci < valueNodes.getLength(); ci++) {
						Node cn = valueNodes.item(ci);
						String nodename = cn.getLocalName();
						if ("AttributeValue".equals(nodename)) {
							String value = cn.getTextContent().trim();
							attributeMap.put(name, value);
						}
					}
				}
			}
		} catch (XPathExpressionException e) {
			_logger.error("Exception when getting attributes: {}", e.getMessage(), e);
			return;
		}
		
		_responseAttributes = attributeMap;
	}
	
	/**
	 * Retrieve a list key->value of attributes in the attributestatement 
	 * @return list, or null when error occurred
	 */
	public Map<String, String> getAttributes()
	{
		if (_responseAttributes == null) parseAttributes();
		
		return _responseAttributes;
	}
}
