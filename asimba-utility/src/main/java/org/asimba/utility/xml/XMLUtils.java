/*
 * Asimba Server
 * 
 * Copyright (C) 2013 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
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
package org.asimba.utility.xml;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;


/**
 * Reusable XML/DOM processing functions
 * 
 * @author mdobrinic
 *
 */
public class XMLUtils {
	
	/**
	 * Local logger instance
	 */
	private static Log _oLogger = LogFactory.getLog(XMLUtils.class);
	

	/**
	 * Create the DOM Document from the XML-document in the provided string
	 * @param sXML String representation of an XML document
	 * @return DOM Document representation of the XML document
	 * @throws OAException when something goes wrong
	 */
	public static Document getDocumentFromString(String sXML)
		throws OAException
	{
		DocumentBuilderFactory oDocumentBuilderFactory = 
				DocumentBuilderFactory.newInstance();

		try {
			DocumentBuilder oDocumentBuilder;
			oDocumentBuilder = oDocumentBuilderFactory.newDocumentBuilder();

			InputSource is = new InputSource(new StringReader(sXML));
			return oDocumentBuilder.parse(is);
		} catch (ParserConfigurationException e) {
			_oLogger.error("Exception before processing the XML document: "+e.getMessage());
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		} catch (SAXException e) {
			_oLogger.warn("SAX Exception when parsing the XML-document"+e.getMessage()+
					"Document was: \n"+sXML);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		} catch (IOException e) {
			_oLogger.warn("IO Exception when parsing the XML-document"+e.getMessage()+
					"Document was: \n"+sXML);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}
	}
	
	
	/**
	 * Create a String representation of the XML-document in the provided DOM Document  
	 * @param eDocument DOM representation of the XML document
	 * @return String representation of the provided XML document, or null when document 
	 * 	could not be transformed
	 * @throws OAException when transformation could not be started
	 */
	public static String getStringFromDocument(Document eDocument)
		throws OAException
	{
		String sResult = null;
		
		try {
			// Build serializable metadata
			TransformerFactory oTransformerFactory = TransformerFactory.newInstance();
			Transformer oSerializer;
			oSerializer = oTransformerFactory.newTransformer();
	
			StringWriter oStringWriter = new StringWriter();
	
			oSerializer.transform(new DOMSource(eDocument), new StreamResult(oStringWriter));
			
			sResult = oStringWriter.toString();
			
			return sResult;
			
		} catch (TransformerConfigurationException e) {
			_oLogger.error("Exception when getting transformer for document transformation: "+e.getMessage());
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		} catch (TransformerException e) {
			_oLogger.error("Exception when transforming document to DOM: "+e.getMessage());
			return null;
		}
		
	}
}
