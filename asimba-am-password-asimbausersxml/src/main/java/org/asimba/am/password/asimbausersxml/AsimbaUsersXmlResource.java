/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
package org.asimba.am.password.asimbausersxml;

import java.io.File;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.log4j.Logger;
import org.asimba.utility.filesystem.PathTranslator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractResourceHandler;

public class AsimbaUsersXmlResource extends AbstractResourceHandler {

	private Logger _oLogger;
	
	
	/**
	 * Full qualified filename of the asimba-users.xml file
	 * <br/>Configurable in &lt;file&gt element
	 * <br/>Translated using virtual mountingpoints, 
	 * i.e. &lt;file&gt;${webapp.root}/WEB-INF/sample-data/asimba-users.xml&lt;/file&gt;
	 */
	protected String _sAsimbaUsersXmlFilename;
	
	
	
	/**
	 * Default constructor
	 */
	public AsimbaUsersXmlResource() {
		super();
		_oLogger = Logger.getLogger(AsimbaUsersXmlResource.class);
	}
	
	
	/**
	 * Authenticate the given user with the provided password; will re-read
	 * the file every time the method is called.
	 * <br/><br/>
	 * This implementation does not do any optimization whatsoever, and is
	 * purely meant for demonstration purposes. Use it wisely.
	 */
	public boolean authenticate(String password, String username)
			throws UserException, OAException 
	{
		// Open the file for reading:
		try {
			DocumentBuilderFactory oDBF = DocumentBuilderFactory.newInstance();
			DocumentBuilder oDocBuilder = oDBF.newDocumentBuilder();
			Document oDoc = oDocBuilder.parse(_sAsimbaUsersXmlFilename);
			
			String sXPathToUserPassword;
			sXPathToUserPassword = "//user[@id='"+username+"']/authMethod[@type='password-plain']/property[@name='password']";
			
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression expr = xpath.compile(sXPathToUserPassword);
			
			String result = (String) expr.evaluate(oDoc, XPathConstants.STRING);

			if (result == null) {
				
				// Try the old way:
				sXPathToUserPassword = "//user[@id='"+username+"']/password";				
				expr = xpath.compile(sXPathToUserPassword);
				result = (String) expr.evaluate(oDoc, XPathConstants.STRING);
				
				if (result == null) {
					_oLogger.info("Could not verify password for user "+username);
					return false;
				}
			}
			
			// Is the password correct?
			if (result.equals(password)) return true;
			
			// Nothing more to try, we fail.
			return false;
			
		} catch (XPathExpressionException e) {
			_oLogger.error("Exception occured; Invalid XPath expression created: "+e.getMessage());
			return false;
		} catch (ParserConfigurationException e) {
			_oLogger.error("Exception occured; Invalid Parser Configuration: "+e.getMessage());
			return false;
		} catch (SAXException e) {
			_oLogger.error("Exception occured; SAX: "+e.getMessage());
			return false;
		} catch (IOException e) {
			_oLogger.error("Exception occured; when reading file: "+e.getMessage());
			return false;
		}
	}

	
	/**
	 * Initialize the AsimbaUsersXmlResource by establishing the filename of the
	 * asimba-users.xml file
	 */
	@Override
	public void init(IConfigurationManager oConfigManager, Element elResourceSection)
			throws OAException 
	{
		// Let abstract parent do its initialization first 
		super.init(oConfigManager, elResourceSection);
		
		if(oConfigManager == null)  {
			_oLogger.error("No configuration manager supplied");
			throw new OAException(SystemErrors.ERROR_INIT);
		}

		String sFilename = oConfigManager.getParam(elResourceSection, "file");
		if(sFilename == null || sFilename.length() <= 0)
		{
			_oLogger.error("No AsimbaUsersXml-file was configured in 'resource' section");
			throw new OAException(SystemErrors.ERROR_INIT);
		}

		_sAsimbaUsersXmlFilename = PathTranslator.getInstance().map(sFilename);

		File oFile = new File(_sAsimbaUsersXmlFilename);
		if (! oFile.exists()) {
			_oLogger.warn("The configured AsimbaUsersXml-file does not exist: "+oFile.getAbsolutePath());
			// do continue starting up though, but no valid authentications can be performed
		}

		_oLogger.info("Started AsimbaUsersXmlResource for "+sFilename);
	}
}
