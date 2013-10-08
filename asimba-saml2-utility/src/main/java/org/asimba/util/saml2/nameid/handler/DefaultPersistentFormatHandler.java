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

import java.security.MessageDigest;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Hex;
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
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2Constants;

/**
 * DefaultPersistentFormatHandler generates a Persistent Identifier
 * that is unique, anonymized and consistent within the context of a requestor
 * 
 * To achieve this, an ID is established, either from the authenticated UserID or
 * from the value of a configured attribute-name (must be available!)
 * To this ID, the SALT-value is appended (if it is configured)
 * Next, a requestor-specific context is added ('!EntityID' is appended to ID)
 * (adding this requestor-specific context is configurable through ignoreRequestorContext)
 * Finally, when opaque is enabled, a hash is calculated over the value
 * 
 * The result is returned
 * 
 * Example configuration:
 * <format type="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
 *   <opaque enabled="true" salt="toomuchisbadforyou" />
 *   <attribute name="#altUID" removeAfterUse="true" />
 *   <ignoreRequestorContext value="true" />
 * </format>
 * 
 * 
 * @author mdobrinic
 *
 */
public class DefaultPersistentFormatHandler implements INameIDFormatHandler {
	
	/**
	 * configuration element names
	 */
	public static final String EL_OPAQUE = "opaque";
	public static final String EL_ATTR_ENABLED = "enabled";
	public static final String EL_ATTR_SALT = "salt";
	public static final String EL_ATTRIBUTE = "attribute";
	public static final String EL_ATTR_NAME = "name";
	public static final String EL_ATTR_REMOVE = "removeAfterUse";	// default: true
	public static final String EL_IGNORE_REQUESTORCTX = "ignoreRequestorContext";	// default: false
	public static final String EL_ATTR_VALUE = "value";
	

	/**
	 * Local logger instance
	 */
    private static final Log _oLogger = LogFactory.getLog(DefaultPersistentFormatHandler.class);

	/**
	 * Reference to the owner NameIDFormatter instance
	 */
	protected NameIDFormatter _oParentFormatter;
	
	protected CryptoManager _oCrypoManager;
	protected SecureRandom _oSecureRandom;
	
	
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
	 * True when using Opaque Persistent Identifiers
	 */
	protected Boolean _bUseOpaque;
	
	/**
	 * Salt to use for generating opaque Identifiers
	 */
	protected String _sSalt;
	
	/**
	 * Flag to indicate whether to include the EntityID in the
	 * resulting NameID value or leave it out
	 * Default: false (do not ignore)
	 */
	protected Boolean _bIgnoreRequestorContext;
	

	public String format(IUser oUser, String sEntityID, String sTGTID,
			ISession oSession) throws OAException 
	{
		String s = null;
		
		// Establish base value from attribute, or oUser's ID: 
		s = getUserAttributeValue(oUser, _sAttributeName, _bRemoveAfterUse);
		
		if (s == null) s = oUser.getID();
		
		// Next, work with the salt if opaque identifiers are enabled and salt is provided:
		if (_bUseOpaque && (_sSalt != null)) {
			s += _sSalt;
		}
		
		// Next add EntityID context:
		if (! _bIgnoreRequestorContext) {
			s += "!" + sEntityID;
		}
		
		// Finally, calculate hash over the value:
		if (_bUseOpaque) {
			s = getHash(s);
		}
		
		return s;
	}

	
	public void reformat(IUser oUser, String sEntityID, String sTGTID, 
			ISession oSession) throws OAException 
	{
		// Clean up the attribute if it exists
		if (_bRemoveAfterUse) {
			oUser.getAttributes().remove(_sAttributeName);
		}
	}
	
	
	protected String getUserAttributeValue(IUser oUser, String sAttributeName, boolean bRAU) {
		String s = null;
		
		if (sAttributeName != null) {
			IAttributes oAttributes = oUser.getAttributes();
			if (oAttributes == null || !oAttributes.contains(sAttributeName)) {
				_oLogger.info("Attribute '"+sAttributeName+"' is not available for user '"+
						oUser.getID()+"'");
			}
			s = (String) oAttributes.get(sAttributeName);
			
			if (bRAU)
				oUser.getAttributes().remove(sAttributeName);
		}
		
		return s;
		
	}
	
	/**
	 * Helper function to create a hash value over a provided string
	 * Hashing algorithm is taken from globally configured MessageDigest
	 * algorithm of CryptoManager
	 * @param sSource String to use as input for the hashing
	 * @return
	 * @throws OAException
	 */
	protected String getHash(String sSource) 
		throws OAException
	{
		String sResult = null;
		
        MessageDigest oMessageDigest = _oCrypoManager.getMessageDigest();
        try
        {
            oMessageDigest.update(sSource.getBytes(SAML2Constants.CHARSET));
            char[] ca = Hex.encodeHex(oMessageDigest.digest());
            sResult = new String(ca);
        }
        catch (Exception e)
        {
            _oLogger.warn("Exception when calculating hash over '"+sSource+"'"); 
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return sResult;
	}
	
	
	/**
	 * Initialize from ConfigManager
	 */
	public void init(IConfigurationManager oConfigManager, Element elConfig, NameIDFormatter oParentFormatter)
			throws OAException 
	{
		_oParentFormatter = oParentFormatter;
		
		// Defaults:
		_bUseOpaque = false;
		_sSalt = null;
		_sAttributeName = null;
		_bIgnoreRequestorContext = false;
		
		Element elOpaque = oConfigManager.getSection(elConfig, EL_OPAQUE);
		if (elOpaque != null) {
			String sOpaqueEnabled = oConfigManager.getParam(elOpaque, EL_ATTR_ENABLED);
			if ("TRUE".equalsIgnoreCase(sOpaqueEnabled)) {
				_bUseOpaque = true;
			} else if (!"FALSE".equalsIgnoreCase(sOpaqueEnabled)) {
				_oLogger.warn("Invalid value for opaque@enabled: "+sOpaqueEnabled);
			}
			
			String sSalt = oConfigManager.getParam(elOpaque, EL_ATTR_SALT);
			if (sSalt != null) {
				_sSalt = sSalt;
			}
			
			_oLogger.info("Opaque set to "+_bUseOpaque+"; salt configured as: "+(_sSalt==null?"not configured":_sSalt));
			
		} else {
			_oLogger.info("No opaque-setting configured; disabling opaque");
		}
		
		Element elAttribute = oConfigManager.getSection(elConfig, EL_ATTRIBUTE);
		if (elAttribute != null) {
			String sName = oConfigManager.getParam(elAttribute, EL_ATTR_NAME);
			if (sName == null) {
				_oLogger.error(EL_ATTRIBUTE+"@"+EL_ATTR_NAME+" must be configured for the element");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			_sAttributeName = sName;
			
			String sRAU = oConfigManager.getParam(elAttribute, EL_ATTR_REMOVE);
			if (sRAU == null) {
				_bRemoveAfterUse = false;
				_oLogger.info("Optional " + EL_ATTRIBUTE+"@"+EL_ATTR_REMOVE+" is not configured, "+
						"using default '"+_bRemoveAfterUse+"'");
			}
			if ("TRUE".equalsIgnoreCase(sRAU)) {
				_bRemoveAfterUse = true;
			} else if (!"FALSE".equalsIgnoreCase(sRAU)) {
				_oLogger.warn("Invalid value for "+EL_ATTRIBUTE+"@"+EL_ATTR_REMOVE+": "+sRAU);
			}
			
			_oLogger.info("Attributename set to "+_sAttributeName+"; the value "+(_bRemoveAfterUse?"WILL":"WILL NOT")+
					" be removed after use.");
		}

		Element elIgnoreRequestorCtx = oConfigManager.getSection(elConfig, EL_IGNORE_REQUESTORCTX);
		if (elIgnoreRequestorCtx != null) {
			String sValue = oConfigManager.getParam(elIgnoreRequestorCtx, EL_ATTR_VALUE);
			if ("TRUE".equalsIgnoreCase(sValue)) {
				_bIgnoreRequestorContext = true;
			} else if (!"FALSE".equalsIgnoreCase(sValue)) {
				_oLogger.warn("Invalid value for "+EL_IGNORE_REQUESTORCTX+"@"+EL_ATTR_VALUE+": "+sValue);
			}
		}
		_oLogger.info("Ignore Requestor in context set to: "+(_bIgnoreRequestorContext?"TRUE":"FALSE"));
		
		
		// Initialize cryptographic context:
		_oCrypoManager = oParentFormatter.getCryptoManager();
		_oSecureRandom = _oCrypoManager.getSecureRandom();
		
		if (_sSalt != null) {
			_oSecureRandom.setSeed(_sSalt.getBytes());
		}
	}

	
	/**
	 * A Persistent Identifier is dependent on a domain 
	 */
	public boolean isDomainScoped() {
		return true;
	}
	
	
	/**
	 * A Persistent Identifier does not have to be unique amongst 
	 *   all (active) TGT's
	 */
	public boolean isDomainUnique() {
		return false;
	}


	/**
	 * A Persistent Identifier is dependent on a domain
	 * Default domain is the EntityID
	 */
	public String getDomain(IUser oUser, String sEntityID) {
		return sEntityID;
	}

}
