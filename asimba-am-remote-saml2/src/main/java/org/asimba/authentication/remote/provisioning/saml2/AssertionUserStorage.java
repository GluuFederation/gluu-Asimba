/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package org.asimba.authentication.remote.provisioning.saml2;

import java.util.Hashtable;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.storage.external.IExternalStorage;

/**
 * AssertionUserStorage is meant to use a SAML2 Assertion as source for a user
 *
 * @author mdobrinic
 *
 */
public class AssertionUserStorage implements IExternalStorage {

	/** Local logger instance */
	private Log _oLogger;
	
	protected Assertion _oAssertion = null; 


	/**
	 * Build the instance based on a provided assertion
	 * @param oAssertion Assertion to use for looking up user
	 */
	public AssertionUserStorage(Assertion oAssertion) {
		_oLogger = LogFactory.getLog(AssertionUserStorage.class);
		_oAssertion = oAssertion;
	}
	
	/**
	 * Initialize the AssertionUserStorage processor
	 * 
	 * The initial version doesn't need to be tweakable.
	 */
	public void start(IConfigurationManager oConfigurationManager,
			Element eConfig) throws UserException 
	{
		return;
	}
	
	/**
	 * Investigate whether the provided sID exists as Subject/NameID-value of the Assertion
	 * Note: no mapping/remappings is done, neither are integrity checks perfomed on NameQualifiers etc.
	 */
	public boolean exists(String sID) throws UserException {
		Subject oSubject = _oAssertion.getSubject();
		NameID oNameID = oSubject.getNameID();
		
		String sAssertionUID = oNameID.getValue();
		
		if (sAssertionUID==null) return false;
		
		return sAssertionUID.equals(sID);
	}

	/**
	 * Nothing to clean up.
	 */
	public void stop() {
		return;
	}

	/**
     * Establish attribute value for user with provided id.
     * This attribute is looked for in the AttributeStatement of the Assertion.
     * The value of the first attribute that is a match will be returned as String.
     * <br/> 
     * <b>Note</b> the provided UserID is ignored; the AttributeStatement(s) of the 
     * Assertion is/are used.
     * 
     * @return null if there was no field for the provided UserID
     * @see IExternalStorage#getField(java.lang.String, java.lang.String)
	 */
	public Object getField(String id, String field) throws UserException {
		List<AttributeStatement> lAttrStatements = _oAssertion.getAttributeStatements();
		
		if (lAttrStatements == null || lAttrStatements.isEmpty()) return null;
		
		// Try to find the attribute from all provided AttributeStatements:
		for (AttributeStatement oAS : lAttrStatements) {
			List<Attribute> lAttrs = oAS.getAttributes();
			
			if (lAttrs == null) continue;
			
			for (Attribute oAttr : lAttrs) {
				String sAttributeName = oAttr.getName();
				
				if (sAttributeName != null) {
					if (sAttributeName.equals(field)) {
						return getAttributeValue(oAttr);
					}
				}
			}
		}

		return null;
	}

	/**
     * Establish all attribute value with a name in 'fields' from the assertion 
     * into a Hashtable
     * The attributes are taken from all AttributeStatements of the Assertion.
     * If there are multiple attributes with the same name, the value that is used
     * is the value of the latest processed Attribute (this is not deterministic)
     * <br/> 
     * <b>Note</b> the provided UserID is ignored; the AttributeStatement(s) of the 
     * Assertion is/are used.
     * 
     * @return map with all attribute->name values from all AttributeStatements
     * @see IExternalStorage#getFields(java.lang.String, java.util.List)	 */
	public Hashtable<String, Object> getFields(String id, List<String> lFields)
			throws UserException 
	{
		Hashtable<String, Object> htValues = new Hashtable<String, Object>();
		
		List<AttributeStatement> lAttrStatements = _oAssertion.getAttributeStatements();
		
		if (lAttrStatements == null || lAttrStatements.isEmpty()) return null;
		
		// Try to find the attribute from all provided AttributeStatements:
		for (AttributeStatement oAS : lAttrStatements) {
			List<Attribute> lAttrs = oAS.getAttributes();
			
			if (lAttrs == null) continue;
			
			for (Attribute oAttr : lAttrs) {
				String sAttributeName = oAttr.getName();
				
				if (lFields.contains(sAttributeName)) {
					String sValue = getAttributeValue(oAttr);
					
					if (sValue != null) {
						htValues.put(sAttributeName, sValue);
					}
				}
			}
		}
		
		return htValues;
	}

	
	/**
	 * Helper to get String-value of a XSString/XSAny type OpenSAML AttributeStatement/Attribute 
	 * @param oAttribute Attribute to get value from
	 * @return String of value, or null if value could not be established (wrong type?)
	 */
	protected String getAttributeValue(Attribute oAttribute) {
        XMLObject oXML = oAttribute.getAttributeValues().get(0);
        String sValue = null;
        
        if (oXML instanceof XSString) {
            XSString oXSString = (XSString)oAttribute.getAttributeValues().get(0);
            sValue = oXSString.getValue();
        } else if (oXML instanceof XSAny) {
            XSAny oXSAny = (XSAny)oAttribute.getAttributeValues().get(0);
            sValue = oXSAny.getTextContent();
        }
        if (sValue == null) {
            _oLogger.debug("Could not get value for attribute " + oAttribute.getName());
        }
        
        return sValue;
		
	}
}
