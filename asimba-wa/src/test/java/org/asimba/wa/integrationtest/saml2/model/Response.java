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

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.asimba.utility.xml.XMLUtils;
import org.asimba.wa.integrationtest.util.SignatureHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.alfaariss.oa.OAException;

public class Response extends SAMLMessage {

	private static final Logger _logger = LoggerFactory.getLogger(Response.class);

	/** contains the parsed inbound SAML Response message */
	private Document _responseDocument = null;


	private String _id;
	private String _issueInstant;
	private String _inResponseTo;
	private String _statusCode;
	private String _subStatusCode;
	private String _destination;

	private Assertion _assertion;


	public Response()
	{
		// Generate some defaults:
		_id="_"+UUID.randomUUID().toString();		
		SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'H:mm:ss");
		simpleDf.setTimeZone(TimeZone.getTimeZone("GMT"));
		_issueInstant = simpleDf.format(new Date());

		_statusCode = "urn:oasis:names:tc:SAML:2.0:status:Success";
	}

	public Document getResponseDocument()
	{
		return _responseDocument;
	}

	public void loadResponse(String responseString)
	{
		try {
			_responseDocument = XMLUtils.getDocumentFromString(responseString, true);

			_assertion = new Assertion();
			_assertion.loadFromResponse(responseString);

		} catch (OAException oae) {
			_logger.error("Could not parse SAML Response document: {}", oae.getMessage(), oae);
		}
	}


	public void init(String issuer, String destination, String inResponseTo, String audience)
	{
		setIssuer(issuer);
		setDestination(destination);
		setInResponseTo(inResponseTo);

		// TODO: Pick this up!
		_assertion = new Assertion();
		_assertion.init(issuer, audience, null);
	}

	public static Response respondToAuthnRequest(String issuer, AuthnRequest authnRequest)
	{
		// create response instance based on inbound AuthnRequest parameters.
		Response response = new Response();

		response.init(issuer,
				authnRequest.getACSURL(),
				authnRequest.getId(),
				authnRequest.getIssuer());

		return response;
	}


	public Assertion getAssertion()
	{
		return _assertion;
	}

	/**
	 * Retrieve the value of the StatusCode element
	 * 
	 * @return value, or null when error occurred
	 */
	public String getStatusCode()
	{
		if (StringUtils.isEmpty(_statusCode)) {
			String xpathQuery = "/saml2p:Response/saml2p:Status/saml2p:StatusCode/@Value";
			_statusCode = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _statusCode;
	}

	public void setStatusCode(String statusCode)
	{
		_statusCode = statusCode;
	}


	/**
	 * Retrieve the value of the InResponseTo element
	 * @return
	 */
	public String getInResponseTo()
	{
		if (StringUtils.isEmpty(_inResponseTo)) {
			String xpathQuery = "/saml2p:Response/@InResponseTo";
			_inResponseTo = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _inResponseTo;
	}

	public void setInResponseTo(String inResponseTo)
	{
		_inResponseTo = inResponseTo;
	}


	/**
	 * Retrieve the value of the Id attribute
	 * @return
	 */
	public String getId()
	{
		if (StringUtils.isEmpty(_id)) {
			String xpathQuery = "/saml2p:Response/@ID";
			_id = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _id;
	}

	public void setID(String id)
	{
		_id = id;
	}


	@Override
	public String getIssuer() 
	{
		if (StringUtils.isEmpty(_issuer)) {
			String xpathQuery = "/saml2p:Response/saml:Issuer";
			_issuer = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _issuer;
	}

	/**
	 * Retrieve the value of the IssueInstant attribute
	 * @return
	 */
	public String getIssueInstant()
	{
		if (StringUtils.isEmpty(_issueInstant)) {
			String xpathQuery = "/saml2p:Response/@IssueInstant";
			_issueInstant = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _issueInstant;
	}

	public void setIssueInstant(String issueInstant)
	{
		_issueInstant = issueInstant;
	}


	/**
	 * Retrieve the value of the Destination element
	 * @return
	 */
	public String getDestination()
	{
		if (StringUtils.isEmpty(_destination)) {
			String xpathQuery = "/saml2p:Response/@Destination";
			_destination = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _destination;
	}

	public void setDestination(String destination)
	{
		_destination = destination;
	}


	/**
	 * Retrieve the value of the StatusCode@Value element that is child of another StatusCode element
	 * @return
	 */
	public String getSubStatusCode()
	{
		if (StringUtils.isEmpty(_subStatusCode)) {
			String xpathQuery = "/saml2p:Response/saml2p:Status/saml2p:StatusCode/saml2p:StatusCode/@Value";
			_subStatusCode = executeXPathValueQuery(xpathQuery, _responseDocument);
		}
		return _subStatusCode;
	}

	public void setSubStatusCode(String subStatusCode)
	{
		_subStatusCode = subStatusCode;
	}


	protected void writeStatus(XMLStreamWriter writer) throws XMLStreamException
	{
		writer.writeStartElement("saml2p","Status","urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeStartElement("saml2p","StatusCode","urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeAttribute("Value", _statusCode);
		writer.writeEndElement();
		writer.writeEndElement();
	}


	/**
	 * Build response based on current state.<br/>
	 * Only do Base64-encoding of the XML-document -- no deflating whatsoever may be done.
	 * 
	 * @return
	 * @throws XMLStreamException 
	 */
	public String getResponse(int format) throws XMLStreamException
	{
		_logger.info("For ID: "+getId());
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		StringWriter sw = new StringWriter();

		XMLOutputFactory factory = XMLOutputFactory.newInstance();
		XMLStreamWriter writer = null;

		// ugly but effective:
		if (format == base64)
		{
			writer = factory.createXMLStreamWriter(baos);
		}
		else
		{
			writer = factory.createXMLStreamWriter(sw);
		}

		writer.writeStartElement("saml2p", "Response", "urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeNamespace("saml2p","urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeNamespace("xs", "http://www.w3.org/2001/XMLSchema");

		writer.writeAttribute("Destination", _destination);
		writer.writeAttribute("ID", _id);
		writer.writeAttribute("InResponseTo", _inResponseTo);
		writer.writeAttribute("IssueInstant", _issueInstant);
		writer.writeAttribute("Version", "2.0");

		writeIssuer(writer);

		writeStatus(writer);

		_assertion.writeAssertion(writer);

		writer.writeEndElement();	// SAML2

		writer.flush();		

		if (format == base64) {
			byte [] bain = baos.toByteArray(); 
			byte [] encoded = Base64.encodeBase64(bain, false);
			String result = new String(encoded, Charset.forName("UTF-8"));

			return result;
		}
		else
		{
			return sw.toString();
		}
	}

	public String getSignedMessage(SignatureHelper signatureHelper) 
	{
		if (_responseDocument == null) 
		{
			try 
			{
				_responseDocument = XMLUtils.getDocumentFromString(getResponse(plain), true);
			} catch (OAException | XMLStreamException e) 
			{
				_logger.error("Problem when establishing XML document to sign: {}", e.getMessage(), e);
				return null;
			}
		}

		signatureHelper.tagIdAttributes(_responseDocument);

		KeyPair keypair = signatureHelper.getKeyPairFromKeystore();

		// Set signing context with PrivateKey and root of the Document
		DOMSignContext dsc = new DOMSignContext(keypair.getPrivate(), 
				_responseDocument.getDocumentElement());

		// Get SignatureFactory for creating signatures in DOM:
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM"); 

		Reference ref = null;
		SignedInfo si = null;
		XMLSignature signature = null;

		try {
			// Create reference for "" -> root of the document
			// SAML requires enveloped transform
			List<Transform> transformsList = new ArrayList<>();
			transformsList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
			// transformsList.add(fac.newTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS, (TransformParameterSpec) null));
			
			ref = fac.newReference(
					"#"+getId(),
					fac.newDigestMethod(DigestMethod.SHA1, null),
					transformsList, 
					null, 
					null);

			// Create SignedInfo (SAML2: Exclusive with or without comments is specified)
			// .. some selection here; nothing fancy, just trying to switch based on signing key format
			String sigMethod;
			String keyAlg = keypair.getPrivate().getAlgorithm();
			if (keyAlg.contains("RSA")) {
				sigMethod = SignatureMethod.RSA_SHA1;
			} else if (keyAlg.contains("DSA")) {
				sigMethod = SignatureMethod.DSA_SHA1;
			} else {
				_logger.error("Unknown signing key algorithm: {}", keyAlg);
				return null;
			}

			si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, 
							(C14NMethodParameterSpec) null),
					fac.newSignatureMethod(sigMethod, null),
					Collections.singletonList(ref));

			// Add KeyInfo to the document:
			KeyInfoFactory kif = fac.getKeyInfoFactory();

			// .. get key from the generated keypair:
			KeyValue kv = kif.newKeyValue(keypair.getPublic());
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

			signature = fac.newXMLSignature(si, ki);

			// Sign!
			signature.sign(dsc);

			String s = XMLUtils.getStringFromDocument(_responseDocument);
			_logger.info("Document after signing whole message:\n{}", s);
			return s;

		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			_logger.error("Could not create reference to signable content: {}", e.getMessage(), e);
			return null;
		} catch (KeyException e) {
			_logger.error("Could not establish key info: {}", e.getMessage(), e);
			return null;
		} catch (MarshalException | XMLSignatureException e) {
			_logger.error("Error signing document: {}", e.getMessage(), e);
			return null;
		} catch (OAException e) {
			_logger.error("Error creating string from XML document: {}", e.getMessage(), e);
			return null;
		}
	}


	/**
	 * Requires the responseDocument to be already initialized, just adding another
	 * Signature section to the existing documnet
	 * @param signatureHelper
	 * @return
	 */
	public String getMessageWithSignedAssertion(SignatureHelper signatureHelper)
	{
		if (_responseDocument == null) 
		{
			try 
			{
				_responseDocument = XMLUtils.getDocumentFromString(getResponse(plain), true);
			} catch (OAException | XMLStreamException e) 
			{
				_logger.error("Problem when establishing XML document to sign: {}", e.getMessage(), e);
				return null;
			}
		}
		
		KeyPair keypair = signatureHelper.getKeyPairFromKeystore();
		
		// Set signing context with PrivateKey and root of the Document
		Node localRoot = _assertion.getAssertionNode();
		signatureHelper.tagIdAttributes(localRoot.getOwnerDocument());

		DOMSignContext dsc = new DOMSignContext(keypair.getPrivate(), localRoot);

		// Get SignatureFactory for creating signatures in DOM:
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM"); 


		Reference refAssertion = null;
		SignedInfo si = null;
		XMLSignature signature = null;

		try {
			// Create reference for "" -> Assertion in the document
			// SAML requires enveloped transform
			List<Transform> transformsList = new ArrayList<>();
			transformsList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
			// transformsList.add(fac.newTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS, (TransformParameterSpec) null));
			
			refAssertion = fac.newReference(
					"#"+getAssertion().getId(),
					fac.newDigestMethod(DigestMethod.SHA1, null),
					transformsList, 
					null, 
					null);
			
			// Create SignedInfo (SAML2: Exclusive with or without comments is specified)
			// .. some selection here; nothing fancy, just trying to switch based on signing key format
			String sigMethod;
			String keyAlg = keypair.getPrivate().getAlgorithm();
			if (keyAlg.contains("RSA")) {
				sigMethod = SignatureMethod.RSA_SHA1;
			} else if (keyAlg.contains("DSA")) {
				sigMethod = SignatureMethod.DSA_SHA1;
			} else {
				_logger.error("Unknown signing key algorithm: {}", keyAlg);
				return null;
			}

			
			si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
					fac.newSignatureMethod(sigMethod, null),
					Collections.singletonList(refAssertion));

			// Add KeyInfo to the document:
			KeyInfoFactory kif = fac.getKeyInfoFactory();

			// .. get key from the generated keypair:
			KeyValue kv = kif.newKeyValue(keypair.getPublic());
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

			signature = fac.newXMLSignature(si, ki);

			// before:
			_logger.info("Signing assertion in document");
//			_logger.info("Document to sign:\n{}", XMLUtils.getStringFromDocument(localRoot.getOwnerDocument()));
			
			// Sign!
			signature.sign(dsc);

			return XMLUtils.getStringFromDocument(localRoot.getOwnerDocument());

		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			_logger.error("Could not create reference to signable content: {}", e.getMessage(), e);
			return null;
		} catch (KeyException e) {
			_logger.error("Could not establish key info: {}", e.getMessage(), e);
			return null;
		} catch (MarshalException | XMLSignatureException e) {
			_logger.error("Error signing document: {}", e.getMessage(), e);
			return null;
		} catch (OAException e) {
			_logger.error("Error creating string from XML document: {}", e.getMessage(), e);
			return null;
		}
	}

}
