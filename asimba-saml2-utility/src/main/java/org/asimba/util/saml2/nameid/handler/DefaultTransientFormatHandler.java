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

import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.nameid.INameIDFormatHandler;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.util.saml2.NameIDFormatter;

/**
 * Establish Transient Identifier for the context with session and for EntityID
 * 
 * Identifier is guaranteed to be a unique Identifier, presented to the SP
 * Also, if the user visits the SP for more times, it remains the same identifier
 * for as long as the user's session with the IDP is valid 
 * 
 * The length (number of characters) of the result, is configurable
 * 
 * Whether this value is unique, is the responsibility of the instance
 * that is calling this formatter.
 * 
 * Example configuration:
 * <format type="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
 *   <identifier length="32" />
 *   <seed value="somerandomstuff" />
 * </format>
 * 
 * @author mdobrinic
 *
 */
public class DefaultTransientFormatHandler implements INameIDFormatHandler {
	/**
	 * configuration element names
	 */
	public static final String EL_IDENTIFIER = "identifier";
	public static final String EL_ATTR_LENGTH = "length";	// default: 24
	public static final String EL_SEED = "seed";
	public static final String EL_ATTR_VALUE = "value";	// default: null


	/**
	 * Characters allowed in a TransientID
	 */
    public final static char[] TRANSIENT_CHARS = {
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        '1','2','3','4','5','6','7','8','9','0'};

	
	/**
	 * Local logger instance
	 */
    private static final Log _oLogger = LogFactory.getLog(DefaultTransientFormatHandler.class);

	/**
	 * Reference to the owner NameIDFormatter instance
	 */
	protected NameIDFormatter _oParentFormatter;
	
	protected CryptoManager _oCrypoManager;
	protected SecureRandom _oSecureRandom;

	/**
	 * Number of characters that make up a TransientID
	 * Default: 24 
	 */
	protected int _iIdentifierLength = 24;
	
	/**
	 * Externally configurable seed for the random generator
	 */
	protected String _sSeed;
	
	
	public String format(IUser oUser, String sEntityID, String sTGTID,
			ISession oSession) throws OAException 
	{
		StringBuffer sb = new StringBuffer();
		int l = TRANSIENT_CHARS.length;
		
        for (int i = 0; i < _iIdentifierLength; i++)
        {
            int p = _oSecureRandom.nextInt(l);
            sb.append(TRANSIENT_CHARS[p]);
        }
        return sb.toString();
	}
	
	
	public void reformat(IUser oUser, String sEntityID, String sTGTID, 
			ISession oSession) throws OAException 
	{
		// Do nothing
	}

	
	public void init(IConfigurationManager oConfigManager, Element elConfig,
			NameIDFormatter oParentFormatter) throws OAException 
	{
		_oParentFormatter = oParentFormatter;
		
		// Defaults:
		_sSeed = null;
		
		Element elIdentifier = oConfigManager.getSection(elConfig, EL_IDENTIFIER);
		if (elIdentifier != null) {
			String sLength = oConfigManager.getParam(elIdentifier, EL_ATTR_LENGTH);
			
			try {
				_iIdentifierLength = Integer.valueOf(sLength);
			} catch (NumberFormatException nfe) {
				_oLogger.error("Invalid value is configured for "+EL_IDENTIFIER+"@"+EL_ATTR_LENGTH+": "+sLength);
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			
			// SAML specifications: restrict to maximum of 256 characters; saml-core 8.3.8
			if (_iIdentifierLength > 256) {
				_oLogger.error("Invalid value is configured for "+EL_IDENTIFIER+"@"+EL_ATTR_LENGTH+
						": maximum length is 256, configured: "+_iIdentifierLength);
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			
			_oLogger.info("Using transient identifier length of: "+_iIdentifierLength);
			
		} else {
			_oLogger.info("Using default transient identifier length: "+_iIdentifierLength);
		}
		
		Element elSeed = oConfigManager.getSection(elConfig, EL_SEED);
		if (elSeed != null) {
			_sSeed = oConfigManager.getParam(elSeed, EL_ATTR_VALUE);
			
			if (_sSeed == null) {
				_oLogger.warn(EL_SEED+"-element was configured, but no @"+EL_ATTR_VALUE+" attribute was provided");
			} else {
				_oLogger.info("Seed was succesfully configured.");
			}
		}
		
		_oCrypoManager = oParentFormatter.getCryptoManager();
		_oSecureRandom = _oCrypoManager.getSecureRandom();
		
		if (_sSeed != null) {
			_oSecureRandom.setSeed(_sSeed.getBytes());
		}
	}


	/**
	 * A Transient Identifier is dependent on a domain:
	 *   another identifier is provided for every domain it is being requested in 
	 */
	public boolean isDomainScoped() {
		return true;
	}

	
	/**
	 * A Transient Identifier must be unique amongst all (active) TGT's
	 */
	public boolean isDomainUnique() {
		return true;
	}

	
	/**
	 * A Transient Identifier is dependent on a domain
	 *   default domain is the EntityID of the SP
	 */
	public String getDomain(IUser oUser, String sEntityID) {
		return sEntityID;
	}

}
