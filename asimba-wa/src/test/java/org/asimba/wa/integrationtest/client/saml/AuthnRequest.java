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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class AuthnRequest {

	private static final Logger _logger = LoggerFactory.getLogger(AuthnRequest.class);

	private String id;
	private String issueInstant;
	public static final int base64 = 1;
	
	private String _acsUrl;
	private String _issuer;
	
	private String _requestedAuthnContext = null;
	/** Default Requested NameID@Format: */ 
	private String _requestedNameIdFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

	public AuthnRequest(String acsUrl, String issuer)
	{		
		id="_"+UUID.randomUUID().toString();		
		SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'H:mm:ss");
		simpleDf.setTimeZone(TimeZone.getTimeZone("GMT"));
		issueInstant = simpleDf.format(new Date());
		
		_acsUrl = acsUrl;
		_issuer = issuer;
	}
	
	
	/**
	 * Get String with the SAML2 AuthnRequest message
	 * @param format 0=plain, 1=base64
	 * @return
	 * @throws XMLStreamException
	 * @throws IOException
	 */
	public String getRequest(int format) throws XMLStreamException, IOException 
	{
		_logger.info("For ID: "+this.id);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Deflater compresser = new Deflater(Deflater.BEST_COMPRESSION, true);
		DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(baos, compresser);
		StringWriter sw = new StringWriter();

		XMLOutputFactory factory = XMLOutputFactory.newInstance();
		XMLStreamWriter writer = null;

		// ugly but effective:
		if (format == base64)
		{
			writer = factory.createXMLStreamWriter(deflaterOutputStream);
		}
		else
		{
			writer = factory.createXMLStreamWriter(sw);
		}

		writer.writeStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeNamespace("samlp","urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("ID", id);
		writer.writeAttribute("Version", "2.0");
		writer.writeAttribute("IssueInstant", this.issueInstant);
		writer.writeAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		writer.writeAttribute("AssertionConsumerServiceURL", _acsUrl);

		writeIssuer(writer);

		writeNameIDPolicy(writer);

		writeRequestedAuthnContext(writer);

		writer.writeEndElement();
		writer.flush();		

		if (format == base64) {
			deflaterOutputStream.close();
			byte [] encoded = Base64.encodeBase64Chunked(baos.toByteArray());
			String result = new String(encoded,Charset.forName("UTF-8"));

			return result;
		}
		else
		{
			return sw.toString();
		}

	}


	protected void writeIssuer(XMLStreamWriter writer) throws XMLStreamException
	{
		writer.writeStartElement("saml","Issuer","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(_issuer);
		writer.writeEndElement();
	}

	
	protected void writeNameIDPolicy(XMLStreamWriter writer) throws XMLStreamException
	{
		if (_requestedNameIdFormat == null) {
			_logger.info("Skipping NameIDPolicy in request");
			return;
		}
		
		_logger.info("Adding {} as NameIDPolicy@Format", _requestedNameIdFormat);

		writer.writeStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
		writer.writeAttribute("Format", _requestedNameIdFormat);
		writer.writeAttribute("AllowCreate", "true");
		writer.writeEndElement();

	}

	protected void writeRequestedAuthnContext(XMLStreamWriter writer) throws XMLStreamException
	{
		if (_requestedAuthnContext == null) {
			_logger.info("Skipping RequestedAuthnContext in request");
			return;
		}

		_logger.info("Adding {} as RequestedAuthnContext@AuthnContextClassRef", _requestedAuthnContext);
		
		writer.writeStartElement("samlp","RequestedAuthnContext","urn:oasis:names:tc:SAML:2.0:protocol");

		writer.writeAttribute("Comparison", "exact");

		writer.writeStartElement("saml","AuthnContextClassRef","urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
		writer.writeCharacters(_requestedAuthnContext);
		writer.writeEndElement();

		writer.writeEndElement();
	}



	public static String getRidOfCRLF(String what) {
		String lf = "%0D";
		String cr = "%0A";
		String now = lf;

		int index = what.indexOf(now);
		StringBuffer r = new StringBuffer();

		while (index!=-1) {
			r.append(what.substring(0,index));
			what = what.substring(index+3,what.length());

			if (now.equals(lf)) {
				now = cr;
			} else {
				now = lf;
			}

			index = what.indexOf(now);
		}
		return r.toString();
	}


	/** ensures that the ID can be found as ID-attribute */
	private void tagIdAttributes(Document xmlDoc) {
		NodeList nodeList = xmlDoc.getElementsByTagName("*");
		for (int i = 0; i < nodeList.getLength(); i++) {
			Node node = nodeList.item(i);
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				if (node.getAttributes().getNamedItem("ID") != null) {
					((Element) node).setIdAttribute("ID", true);
				}
			}
		}
	}


	/**
	 * Open keystore
	 * @param type probably "JKS"
	 * @param keystoreStream
	 * @param password
	 * @return
	 */
	private KeyStore getKeystore(String type, InputStream keystoreStream, String password)
	{
		KeyStore keystore;
		try {
			keystore = KeyStore.getInstance(type);
			keystore.load(keystoreStream, password.toCharArray());

			return keystore;
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException
				| IOException e) 
		{
			// Could not load keystore
			e.printStackTrace();
			return null;
		}
	}


	private KeyPair getKeyPairFromKeystore(KeyStore keystore, String keyAlias, String keyPassword)
	{
		try 
		{
			PasswordProtection passwordProtected = new PasswordProtection(keyPassword.toCharArray());
			Entry keyEntry = keystore.getEntry(keyAlias, passwordProtected);

			if (! (keyEntry instanceof PrivateKeyEntry))
			{
				// Invalid key entry
				return null;
			}
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) keyEntry;
			return new KeyPair(pkEntry.getCertificate().getPublicKey(), pkEntry.getPrivateKey());

		} 
		catch (KeyStoreException
				| NoSuchAlgorithmException | UnrecoverableEntryException e) 
		{
			// Problem occurred
			e.printStackTrace();
			return null;
		}
	}


	// Get signed XML document
	public String getSignedRequest(int format, InputStream keystoreStream, String keystorePassword, 
			String keyAlias, String keyPassword)
	{
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		DocumentBuilder builder;
		Document doc;
		try {
			builder = dbf.newDocumentBuilder();
			doc = builder.parse(
					new InputSource(new ByteArrayInputStream(getRequest(0).getBytes("utf-8")))
					);

			// Prepare doc by marking attributes as referenceable:
			tagIdAttributes(doc);

			// Prepare cryptographic environemnt
			KeyStore keystore = getKeystore("JKS", keystoreStream, keystorePassword);
			if (keystore == null) return null;

			KeyPair kp;

			kp = getKeyPairFromKeystore(keystore, keyAlias, keyPassword);
			if (kp == null)
			{
				// Generate key, to prove that it works...
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
				kpg.initialize(512);
				kp = kpg.generateKeyPair();
			}

			// Set signing context with PrivateKey and root of the Document
			DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc.getDocumentElement());

			// Get SignatureFactory for creating signatures in DOM:
			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM"); 

			// Create reference for "" -> root of the document
			// SAML requires enveloped transform
			Reference ref = fac.newReference(
					"#"+this.id,
					fac.newDigestMethod(DigestMethod.SHA1, null),
					Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), 
					null, 
					null); 

			// Create SignedInfo (SAML2: Exclusive with or without comments is specified)
			SignedInfo si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null),
					fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null),
					Collections.singletonList(ref));

			// Add KeyInfo to the document:
			KeyInfoFactory kif = fac.getKeyInfoFactory();

			// .. get key from the generated keypair:
			KeyValue kv = kif.newKeyValue(kp.getPublic());
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

			XMLSignature signature = fac.newXMLSignature(si, ki);

			String before = docToString(doc);

			// Sign!
			signature.sign(dsc);

			String after = docToString(doc);

			System.out.println("Before: " + before);
			System.out.println("After : " + after);

			return after;

		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XMLStreamException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// key generation exception
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// digest algorithm selection exception
			e.printStackTrace();
		} catch (KeyException e) {
			// when key-value was not available (when adding to KeyInfo)
			e.printStackTrace();
		} catch (MarshalException e) {
			// sign didn't work:
			e.printStackTrace();
		} catch (XMLSignatureException e) {
			// sign didn't work:
			e.printStackTrace();
		}  
		return null;
	}

	private String docToString(Document doc)
	{
		String result = null;

		try {

			// Build serializable metadata
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer serializer;
			serializer = transformerFactory.newTransformer();

			serializer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
			serializer.setOutputProperty(OutputKeys.INDENT, "yes");

			StringWriter stringWriter = new StringWriter();

			serializer.transform(new DOMSource(doc), new StreamResult(stringWriter));

			result = stringWriter.toString();

			return result;

		} catch (TransformerConfigurationException e) {
			// _logger.error("Exception when getting transformer for document transformation: "+e.getMessage());
			return null;
		} catch (TransformerException e) {
			// _logger.error("Exception when transforming document to DOM: "+e.getMessage());
			return null;
		}
	}

}
