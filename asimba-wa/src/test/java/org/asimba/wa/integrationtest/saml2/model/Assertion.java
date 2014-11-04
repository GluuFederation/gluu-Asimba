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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.UUID;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.StringUtils;
import org.asimba.utility.xml.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.alfaariss.oa.OAException;

/**
 * 
 * @author mdobrinic
 */
public class Assertion extends SAMLMessage {

	private static final Logger _logger = LoggerFactory.getLogger(Assertion.class);

	public static final String DEFAULT_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
	
	private Document _responseDocument;
	
	/** lazy initialized parsed attributes from the Response */
	transient private Map<String, String> _responseAttributes = null;
	private boolean _parseAttributes = false;	// whenever attributes should be parsed

	private String _id;	// generated
	private String _issueInstant;	// generated
	
	private int _numSecondsBefore = 60;
	private String _condNotBefore;	// used in Conditions@NotBefore	// generated
	private int _numSecondsOnOrAfter = 300;
	private String _condNotOnOrAfter;	// used in Conditions@NotOnOrAfter	// generated
	
	private String _audience;	// one audience, used in Conditions/AudienceRestriction
	
	private String _subjectNameId;
	private String _subjectNameIdFormat;
	
	private String _sessionIndex;	// generated
	private int _numSecondsSessionLifetime = 60*60*100;
	private String _sessionNotOnOrAfter;	// used in AuthnStatement@SessionNotOnOrAfter
	
	private String _authnContextClassRef;	// used in AuthnStatement/AuthnContext

	
	
	
	public Assertion()
	{
		_id="_"+UUID.randomUUID().toString();		
		SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'H:mm:ss");
		simpleDf.setTimeZone(TimeZone.getTimeZone("GMT"));
		
		long now = System.currentTimeMillis();
		_issueInstant = simpleDf.format(new Date(now));
		_condNotBefore = simpleDf.format(new Date(now - (_numSecondsBefore * 1000)));
		_condNotOnOrAfter = simpleDf.format(new Date(now + (_numSecondsOnOrAfter * 1000)));
		
		_sessionIndex = _id + "_" + UUID.randomUUID().toString();
		_sessionNotOnOrAfter = simpleDf.format(new Date(now + (_numSecondsSessionLifetime * 1000)));
		
		_authnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
		
		_parseAttributes = true;				
	}
	
	public void init(String issuer, String audience, String subjectNameId)
	{
		init(issuer, audience, subjectNameId, DEFAULT_NAMEID_FORMAT);
	}
	
	public void init(String issuer, String audience, String subjectNameId, String subjectNameIdFormat)
	{
		_issuer = issuer;
		_audience = audience;
		_subjectNameId = subjectNameId;
		_subjectNameIdFormat = subjectNameIdFormat;
	}
	
	private void reset()
	{
		_id = null;
		_issueInstant = null;
		_condNotBefore = null;
		_condNotOnOrAfter = null;
		_sessionIndex = null;
		_sessionNotOnOrAfter = null;
		_authnContextClassRef = null;
	}
	
	/**
	 * The responseString that is provided here, contains the whole Response document.<br/>
	 * That means that the root element is a saml2p:Response element.<br/>
	 * Also: there is exactly one /Response/Assertion element, that is being used to get data
	 * from.<br/>
	 * Note: the writeAssertion() function writes a <saml2:Assertion>...</saml2:Assertion> string. 
	 * @param responseString
	 */
	public void loadFromResponse(String responseString)
	{
		try {
			_responseDocument = XMLUtils.getDocumentFromString(responseString, true);
			
			_parseAttributes = true;
			_responseAttributes = null;
			
			reset();	// all generated values must be (lazily) initialized from document
		} catch (OAException oae) {
			_logger.error("Could not parse SAML Response document in Assertion: {}", oae.getMessage(), oae);
		}
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
	public Map<String, String> getParsedAttributes()
	{
		if (_parseAttributes) parseAttributes();
		
		return _responseAttributes;
	}
	
	
	public Map<String, String> getAttributes()
	{
		if (_responseAttributes == null) _responseAttributes = new HashMap<>();
		
		return _responseAttributes;
	}
	
	public void setAttributes(Map<String, String> map)
	{
		_responseAttributes = map;
	}
	
	
	public Node getAssertionNode()
	{
		if (_responseDocument == null) return null;
		
		String xpathQuery = "/saml2p:Response/saml2:Assertion";
		
		XPath xpath = XPathFactory.newInstance().newXPath();
		xpath.setNamespaceContext(new SimpleSAMLNamespaceContext(null));
		
		try 
		{
			return (Node) xpath.compile(xpathQuery).evaluate(_responseDocument, XPathConstants.NODE);
		} 
		catch (XPathExpressionException e) 
		{
			_logger.error("Exception when processing XPath Query: {}", e.getMessage(), e);
			return null;
		}
		
	}
	
	
	/**
	 * Retrieve the value of the Subject/NameId element
	 * @return value, or null when error occurred
	 */
	public String getSubjectNameId()
	{
		if (StringUtils.isEmpty(_subjectNameId)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID";
			_subjectNameId = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _subjectNameId;
	}
	
	public void setSubjectNameId(String subjectNameId)
	{
		_subjectNameId = subjectNameId;
	}
	
	/**
	 * Retrieve the value of the Subject/NameId@Format attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getSubjectNameIdFormat()
	{
		if (StringUtils.isEmpty(_subjectNameIdFormat)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID/@Format";
			_subjectNameIdFormat = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _subjectNameIdFormat;
	}
	
	public void setSubjectNameIdFormat(String subjetNameIdFormat)
	{
		_subjectNameIdFormat = subjetNameIdFormat;
	}

	
	/**
	 * Retrieve the value of the Conditions/AudienceRestrictions/Audience attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getAudience()
	{
		if (StringUtils.isEmpty(_audience)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:Conditions/saml2:AudienceRestriction/saml2:Audience";
			_audience = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _audience;
	}
	
	public void setAudience(String audience)
	{
		_audience = audience;
	}
 
	/**
	 * Retrieve the value of the Assertion@IssueInstant attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getIssueInstant()
	{
		if (StringUtils.isEmpty(_issueInstant)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/@IssueInstant";
			_issueInstant = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _issueInstant;
	}
	
	public void setIssueInstant(String issueInstant)
	{
		_issueInstant = issueInstant;
	}
	
	
	/**
	 * Retrieve the value of the Conditions@NotBefore attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getCondNotBefore()
	{
		if (StringUtils.isEmpty(_condNotBefore)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:Conditions/@NotBefore";
			_condNotBefore = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _condNotBefore;
	}
	
	public void setCondNotBefore(String condNotBefore)
	{
		_condNotBefore = condNotBefore;	
	}
	

	/**
	 * Retrieve the value of the Conditions@NotAfter attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getCondNotAfter()
	{
		if (StringUtils.isEmpty(_condNotOnOrAfter)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:Conditions/@NotAfter";
			_condNotOnOrAfter = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _condNotOnOrAfter;
	}
	
	public void setCondNotAfter(String condNotAfter)
	{
		_condNotOnOrAfter = condNotAfter;	
	}
	
	
	/**
	 * Retrieve the value of the AuthnStatement@SessionIndex attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getSessionIndex()
	{
		if (StringUtils.isEmpty(_sessionIndex)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:AuthnStatement/@SessionIndex";
			_sessionIndex = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _sessionIndex;
	}
	
	public void setSessionIndex(String sessionIndex)
	{
		_sessionIndex = sessionIndex;
	}
	
	
	/**
	 * Retrieve the value of the AuthnStatement@SessionNotOnOrAfter attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getSessionNotOnOrAfter()
	{
		if (StringUtils.isEmpty(_sessionNotOnOrAfter)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:AuthnStatement/@SessionNotOnOrAfter";
			_sessionNotOnOrAfter = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _sessionNotOnOrAfter;
	}
	
	public void setSessionNotOnOrAfter(String sessionNotOnOrAfter)
	{
		_sessionNotOnOrAfter = sessionNotOnOrAfter;	
	}

	
	/**
	 * Retrieve the value of the AuthnStatement@SessionIndex attribute
	 * @return value, or null when error occurred
	 * @return
	 */
	public String getAuthnContextClassRef()
	{
		if (StringUtils.isEmpty(_authnContextClassRef)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:AuthnStatement/saml2:AuthnContext/saml2:AuthnContextClassRef";
			_authnContextClassRef = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _authnContextClassRef;
	}
	
	public void setAuthnContextClassRef(String authnContextClassRef)
	{
		_authnContextClassRef = authnContextClassRef;
	}
	
	
	/**
	 * Retrieve the value of the Issuer element
	 * @return value, or null when error occurred
	 */
	@Override
	public String getIssuer()
	{
		if (StringUtils.isEmpty(_issuer)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/saml2:Issuer";
			_issuer = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _issuer;
	}
	
	
	public String getId()
	{
		if (StringUtils.isEmpty(_id)) {
			String xpathQuery = "/saml2p:Response/saml2:Assertion/@ID";
			_id = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _id;
	}
	
	
	public void writeSubject(XMLStreamWriter writer) throws XMLStreamException
	{
		writer.writeStartElement("saml2","Subject","urn:oasis:names:tc:SAML:2.0:assertion");
		
		writer.writeStartElement("saml2", "NameID", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeAttribute("Format", getSubjectNameIdFormat());
		writer.writeAttribute("NameQualifier", getIssuer());
		writer.writeCharacters(getSubjectNameId());
		writer.writeEndElement();	// </NameID>
		
		// TODO: Consider whether SubjectConfirmation should also be included or not
		
		writer.writeEndElement();	// </Subject>
	}
	
	
	public void writeConditions(XMLStreamWriter writer) throws XMLStreamException
	{
		writer.writeStartElement("saml2", "Conditions", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeAttribute("NotAfter", getCondNotAfter());
		writer.writeAttribute("NotBefore", getCondNotBefore());
		
		writer.writeStartElement("saml2", "AudienceRestriction", "urn:oasis:names:tc:SAML:2.0:assertion");
		
		writer.writeStartElement("saml2", "Audience", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(getAudience());
		writer.writeEndElement();	// </Audience>
		
		writer.writeEndElement();	// </AudienceRestriction>
		
		writer.writeEndElement();	// </Conditions>
	}
	
	public void writeAuthnStatement(XMLStreamWriter writer) throws XMLStreamException
	{
		writer.writeStartElement("saml2", "AuthnStatement", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeAttribute("AuthnInstant", getIssueInstant());
		writer.writeAttribute("SessionIndex", getSessionIndex());
		writer.writeAttribute("SessionNotOnOrAfter", getSessionNotOnOrAfter());
		
		writer.writeStartElement("saml2", "AuthnContext", "urn:oasis:names:tc:SAML:2.0:assertion");
		
		writer.writeStartElement("saml2", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(getAuthnContextClassRef());
		writer.writeEndElement();	// </AuthnContextClassRef>

		writer.writeEndElement();	// </AuthnContext>
		
		writer.writeEndElement();	// </AuthnStatement>
	}
	
	
	public void writeAttribute(XMLStreamWriter writer, String key, String value) throws XMLStreamException
	{
		writer.writeStartElement("saml2", "Attribute", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeAttribute("Name", key);
		writer.writeAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
		
		writer.writeStartElement("saml2", "AttributeValue", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
		writer.writeAttribute("xsi", "http://www.w3.org/2001/XMLSchema-instance", "type", "xs:string");
		writer.writeCharacters(value);
		writer.writeEndElement();	// </AttributeValue>
		
		writer.writeEndElement();	// </Attribute>
	}
	
	
	public void writeAttributeStatement(XMLStreamWriter writer) throws XMLStreamException
	{
		writer.writeStartElement("saml2", "AttributeStatement", "urn:oasis:names:tc:SAML:2.0:assertion");
		
		// Write each Attribute
		for(Entry<String, String> attribute: getAttributes().entrySet())
		{
			writeAttribute(writer, attribute.getKey(), attribute.getValue());
		}
		
		writer.writeEndElement();	// </AttributeStatement>
	}
	
	public void writeAssertion(XMLStreamWriter writer) throws XMLStreamException
	{
		writer.writeStartElement("saml2","Assertion","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeAttribute("ID", getId());
		writer.writeAttribute("IssueInstant", getIssueInstant());
		writer.writeAttribute("Version", "2.0");
		
		writeIssuer(writer);
		
		writeSubject(writer);
		
		writeConditions(writer);
		
		writeAuthnStatement(writer);
		
		writeAttributeStatement(writer);
		
		writer.writeEndElement();	// </Assertion>

	}

	
	
}
