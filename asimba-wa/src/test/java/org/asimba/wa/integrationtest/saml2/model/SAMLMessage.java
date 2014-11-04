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
package org.asimba.wa.integrationtest.saml2.model;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

/**
 * Some shared facilities for AuthnRequest and Reponse messages
 * 
 * @author mdobrinic
 *
 */
abstract public class SAMLMessage {

	private static final Logger _logger = LoggerFactory.getLogger(SAMLMessage.class);
	
	public static final int base64 = 1;
	public static final int plain = -1;

	
	protected String _issuer;
	
	/**
	 * Execute provided XPath query on document. Query must return String-value, otherwise
	 * unexpected behavior occurs
	 * 
	 * @param xpathQuery XPath Query to perform 
	 * @param document Document to perform query on
	 * @return value, or null when error occurred
	 */
	protected String executeXPathValueQuery(String xpathQuery, Document document)
	{
		if (document == null) {
			_logger.error("No document specified.");
			return null;
		}
		
		XPath xpath = XPathFactory.newInstance().newXPath();
		xpath.setNamespaceContext(new SimpleSAMLNamespaceContext(null));
		
		try 
		{
			return xpath.compile(xpathQuery).evaluate(document);
		} 
		catch (XPathExpressionException e) 
		{
			_logger.error("Exception when processing XPath Query: {}", e.getMessage(), e);
			return null;
		}
	}
	

	abstract public String getIssuer();
	
	public void setIssuer(String issuer)
	{
		_issuer = issuer;
	}

	protected void writeIssuer(XMLStreamWriter writer) throws XMLStreamException
	{
		writer.writeStartElement("saml","Issuer","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(getIssuer());
		writer.writeEndElement();
	}


}
