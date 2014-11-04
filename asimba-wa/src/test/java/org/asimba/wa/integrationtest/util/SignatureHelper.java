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

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SignatureHelper {
	
	private static final Logger _logger = LoggerFactory.getLogger(SignatureHelper.class);

	private KeyStore _keyStore = null;
	private String _keyAlias = null;
	private String _keyPassword = null;
	
	public SignatureHelper()
	{
	}

	
	
	/**
 	 * Open keystore
 	 * @param type probably "JKS"
 	 * @param keystoreStream
 	 * @param password
 	 * @return
 	 */
 	public void setKeystore(String type, InputStream keystoreStream, String password)
 	{
 		KeyStore keyStore;
 		try {
 			keyStore = KeyStore.getInstance(type);
 			keyStore.load(keystoreStream, password.toCharArray());
 			
 			_keyStore = keyStore;
 		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException
 				| IOException e) 
 		{
			_logger.error("Exception when getting keypair: {}", e.getMessage(), e);
 			e.printStackTrace();
 		}
 	}
 	
 	public void setKeyAliasAndPassword(String keyAlias, String keyPassword)
 	{
 		_keyAlias = keyAlias;
 		_keyPassword = keyPassword;
 	}
 	
	
	public KeyPair getKeyPairFromKeystore()
 	{
		try 
		{
			PasswordProtection passwordProtected = new PasswordProtection(_keyPassword.toCharArray());
			Entry keyEntry = _keyStore.getEntry(_keyAlias, passwordProtected);
			
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
			_logger.error("Exception when getting keypair: {}", e.getMessage(), e);
			return null;
		}
 	}
	
	public Certificate getCertificateFromKeystore()
	{
		try 
		{
			PasswordProtection passwordProtected = new PasswordProtection(_keyPassword.toCharArray());
			Entry keyEntry = _keyStore.getEntry(_keyAlias, passwordProtected);
			
			if (! (keyEntry instanceof PrivateKeyEntry))
			{
				// Invalid key entry
				return null;
			}
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) keyEntry;
			return pkEntry.getCertificate();
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException
				| KeyStoreException e) 
		{
			_logger.error("Exception when getting certificate: {}", e.getMessage(), e);
			return null;
		}
	}
	
	
	public String getPEMEncodedCertificateFromKeystore(boolean includeBeginEndEnvelope)
	{
		String beginCertificate = "-----BEGIN CERTIFICATE-----\n";
		String endCertificate = "-----END CERTIFICATE-----";

		String certificateString = getPEMEncodedCertificateFromKeystore();
		
		if (includeBeginEndEnvelope) 
		{
			return beginCertificate + certificateString + endCertificate;	
		}
		else
		{
			return certificateString;
		}
	}
	
	
	public String getPEMEncodedCertificateFromKeystore()
	{
		Certificate certificate = getCertificateFromKeystore();
		Base64 encoder = new Base64(64);
	
		byte[] derCert;
		try 
		{
			derCert = certificate.getEncoded();
			return new String(encoder.encode(derCert));
		} 
		catch (CertificateEncodingException e) 
		{
			_logger.error("Exception: {}", e.getMessage(), e);
			return "NO-CERT";
		}
	}
	
	
 	/** 
 	 * ensures that the ID can be found as ID-attribute
 	 * @param xmlDoc Document to tag ID-elements of 
 	 */
 	public void tagIdAttributes(Document xmlDoc) {
		NodeList nodeList = xmlDoc.getElementsByTagName("*");
		for (int i = 0; i < nodeList.getLength(); i++) {
			Node node = nodeList.item(i);
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				if (node.getAttributes().getNamedItem("ID") != null) {
					_logger.info("Tagging {} with ID attribute.", node.getLocalName());
					((Element) node).setIdAttribute("ID", true);
				}
			}
		}
	}

}
