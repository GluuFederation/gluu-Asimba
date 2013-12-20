/*
 * Asimba Server
 * 
 * Copyright (C) 2013 Asimba
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
package org.asimba.util.saml2.metadata.provider;

import java.util.Set;

import junit.framework.TestCase;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;

import com.alfaariss.oa.OAException;

/**
 * Testcase for monitoring the number of threads that are created to manage
 * MetadataProviders
 * 
 * @author mdobrinic
 *
 */
public class MetadataProviderUtilTest extends TestCase {

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();

		// Ensure OpenSAML is initialized
		DefaultBootstrap.bootstrap();
		// CustomOpenSAMLBootstrap.bootstrap();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	
	/**
	 * Test passes when empty URL is provided, or when valid URL is provided and number of threads
	 * does not increase with each MetadataProvider 
	 * 
	 * Tune settings using:
	 * sMetadataURL : make this point to a source that can be accessed 1000 times per second....
	 * iNumRuns: some high number to ensure that the threadcount doesn't increase for each provider 
	 */
	public void testProviderThreadSafety() {
		MetadataProvider oMP = null;
		XMLObject oXML = null;
		
		// For better testing, use a file based source; 
		// TODO: Set this up through Maven resources???
		String sMetadataURL = ""; // "http://www.asimba.org:8080/asimba-wa/profiles/saml2";
		int iNumRuns = 100;	// increase this as desired
		
		Set<Thread> threadSet_start, threadSet_end;
		
		threadSet_start = Thread.getAllStackTraces().keySet();
		
		// Escape: disables test
		if ("".equals(sMetadataURL)) return;
		
		try {
			for (int i=0; i<iNumRuns; i++) {
				// 
				oMP = MetadataProviderUtil.createProviderForURL(sMetadataURL);
				oXML = oMP.getMetadata();
			}
			
			threadSet_end = Thread.getAllStackTraces().keySet();
			
			// Ensure that no threads have been created, allow for some slack though
			assert(threadSet_end.size() < (threadSet_start.size()+13));
			
		} catch (OAException e) {
			fail("OAException occurred" + e.getMessage());
		} catch (MetadataProviderException e) {
			// TODO Auto-generated catch block
			fail("MetadataProviderException occurred" + e.getMessage());
		}
		
	}
	
}
