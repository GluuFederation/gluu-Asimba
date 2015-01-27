package com.alfaariss.oa.util.saml2.storage.artifact;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.asimba.utility.xml.XMLUtils;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Unmarshaller;
import org.w3c.dom.Document;

public class ArtifactMapEntryTest {

	@Test
	public void artifactMapEntryIsSerializable() throws Exception {
		DefaultBootstrap.bootstrap();

		final String xml = "<saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='Assertion12345789' IssueInstant='2009-07-15T15:42:36.750Z' Version='2.0'><saml:Issuer>http://mycom.com/MyJavaAuthnService</saml:Issuer><saml:Subject><saml:NameID>harold_dt</saml:NameID></saml:Subject><saml:AuthnStatement><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>";
		boolean namespaceAware = true;
		Document document = XMLUtils.getDocumentFromString(xml, namespaceAware);

		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory()
				.getUnmarshaller(document.getDocumentElement());
		Assertion message = (Assertion) unmarshaller.unmarshall(document
				.getDocumentElement());

		ArtifactMapEntry entry = new ArtifactMapEntry("testArtifact",
				"testIssuer", "testRelyingParty", 1000L, message);

		System.out.println("entry: " + entry);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		ObjectOutputStream oos = new ObjectOutputStream(baos);
		
		oos.writeObject(entry);

		byte[] bytes = baos.toByteArray();

		ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(
				bytes));
		
		ArtifactMapEntry copy = (ArtifactMapEntry)in.readObject();

		assertTrue(entry.getArtifact().equals(copy.getArtifact())
				&& entry.getIssuerId().equals(copy.getIssuerId())
				&& entry.getRelyingPartyId().equals(copy.getRelyingPartyId())
				&& entry.getExpirationTime().equals(copy.getExpirationTime())
				&& ((Assertion) entry.getSamlMessage()).getID().equals(
						((Assertion) copy.getSamlMessage()).getID()));
	}
}
