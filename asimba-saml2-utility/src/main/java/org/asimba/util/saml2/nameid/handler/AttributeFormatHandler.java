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
package org.asimba.util.saml2.nameid.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.nameid.INameIDFormatHandler;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.util.saml2.NameIDFormatter;

/**
 * AttributeFormatHandler implements a generic handler that
 * uses a configurable attribute to be the value of the
 * target NameID
 * 
 * Attribute Release Policy has already been applied, so
 * the @removeAfterUse can ensure that the attribute-value
 * is not also contained in provided attributes
 * 
 * Example configuration:
 * <format type="urn:oasis:names:tc:SAML:2.0:nameid-format:...some-format...">
 *   <attribute name="the-attribute" removeAfterUse="true" />
 * </format>
 * 
 * @author mdobrinic
 *
 */
public class AttributeFormatHandler implements INameIDFormatHandler {
	
	/**
	 * configuration element names
	 */
	public static final String EL_ATTRIBUTE = "attribute";
	public static final String EL_ATTR_NAME = "name";
	public static final String EL_ATTR_REMOVE = "removeAfterUse";	// default: true

	/**
	 * Local logger instance
	 */
    private static final Log _oLogger = LogFactory.getLog(AttributeFormatHandler.class);

	/**
	 * Reference to the owner NameIDFormatter instance
	 */
	protected NameIDFormatter _oParentFormatter;
	
	/**
	 * When set, use this as source for NameID, otherwise use
	 * the value of UserID
	 */
	protected String _sAttributeName;
	
	/**
	 * When attribute is specified, remove it from the user's attributes
	 * after it was used to format the Persistent ID
	 * Default: true
	 */
	protected boolean _bRemoveAfterUse;
	
    
	/**
	 * Format the value for NameID for the provided user and context
	 * @param oUser
	 * @param sEntityID
	 * @param sTGTID
	 * @param oSession
	 * @return Formatted NameID value
	 * @throws OAException 
	 */
    public String format(IUser oUser, String sEntityID, String sTGTID,
			ISession oSession) throws OAException 
	{
		// Establish value from attribute 
		IAttributes oAttributes = oUser.getAttributes();
		if (oAttributes == null || !oAttributes.contains(_sAttributeName)) {
			_oLogger.info("Attribute '"+_sAttributeName+"' is not available for user '"+
					oUser.getID()+"'");
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}
		
		String s = (String) oAttributes.get(_sAttributeName);
			
		if (_bRemoveAfterUse) {
			oUser.getAttributes().remove(_sAttributeName);
		}
    
    	return s;
	}

    
    /**
     * Performed in case of already established NameID value
     * Should perform everything, except calculate the value
     * Use this to clean up context (removes attributes also removed
     * using format())
     */
	public void reformat(IUser oUser, String sEntityID, String sTGTID, 
			ISession oSession) throws OAException 
	{
		if (_bRemoveAfterUse) {
			oUser.getAttributes().remove(_sAttributeName);
		}
	}

    
	/**
	 * Initialize the AttributeFormatHandler
	 * @param oConfigManager
	 * @param elConfig
	 * @param oParentFormatter
	 * @throws OAException
	 */
	public void init(IConfigurationManager oConfigManager, Element elConfig,
			NameIDFormatter oParentFormatter) throws OAException 
	{
		_oParentFormatter = oParentFormatter;

		// Defaults:
		_sAttributeName = null;
		
		Element elAttribute = oConfigManager.getSection(elConfig, EL_ATTRIBUTE);
		if (elAttribute != null) {
			String sName = oConfigManager.getParam(elAttribute, EL_ATTR_NAME);
			if (sName == null) {
				_oLogger.error(EL_ATTRIBUTE+"@"+EL_ATTR_NAME+" must be configured for the element");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			_sAttributeName = sName;
			
			String sRAU = oConfigManager.getParam(elAttribute, EL_ATTR_REMOVE);
			if ("TRUE".equalsIgnoreCase(sRAU)) {
				_bRemoveAfterUse = true;
			} else if (!"FALSE".equalsIgnoreCase(sRAU)) {
				_oLogger.warn("Invalid value for opaque@removeAfterUse: "+sRAU);
			}
			
			_oLogger.info("Attributename set to "+_sAttributeName+"; the value "+(_bRemoveAfterUse?"WILL":"WILL NOT")+
					" be removed after use.");
		} else {
			_oLogger.error(EL_ATTRIBUTE+" must be configured for the NameIDFormatter!");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
	}
	
	
	/**
	 * An Attribute Identifier is not dependent on a domain; the same attribute
	 *   can be used as NameID value across all domains
	 */
	public boolean isDomainScoped() {
		return false;
	}


	/**
	 * An Attribute Identifier is not generated, and therefore it is possible that
	 *   multiple (active) TGT's can provide the same NameID value for a domain 
	 */
	public boolean isDomainUnique() {
		return false;
	}

	/**
	 * An Attribute Identifier is not dependent on a domain
	 */
	public String getDomain(IUser oUser, String sEntityID) {
		return null;
	}
}
