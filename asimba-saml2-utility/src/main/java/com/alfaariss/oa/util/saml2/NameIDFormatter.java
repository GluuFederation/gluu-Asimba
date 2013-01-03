/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.util.saml2;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.nameid.INameIDFormatHandler;
import org.opensaml.saml2.core.NameIDType;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;

/**
 * NameID Formatter.
 *
 * History:
 * 2012/11; Componentized the handlers for each format [mdobrinic]
 *
 * @author mdobrinic
 * @author JRE
 * @author MHO
 * @author Alfa & Ariss
 */
public class NameIDFormatter
{
	/**
	 * configuration element names
	 */
	public static final String EL_ATTR_DEFAULT = "default";
	public static final String EL_FORMAT = "format";
	public static final String EL_ID = "id";
	public static final String EL_CLASS = "class";

	
	/**
	 * Static map with supported NameID formats and their default implementations
	 */
	protected static final Map<String, String> mFormatDefaultClass = createFormatDefaultClassMap();
	
    /** Not standard SAML 2.0 Unspecified URI: urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified */
    public final static String SAML20_UNSPECIFIED = 
        "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
    
    /** Type: TGT_ALIAS */
    public final static String TYPE_ALIAS_TGT = "session_index";

    protected static final Map<String, String> mFormatToType = createFormatToTypeMap();
    
    private static final Log _oLogger = LogFactory.getLog(NameIDFormatter.class);
    private CryptoManager _oCryptoManager;
    private ITGTAliasStore _oTGTAliasStore;

    /**
     * Configured NameIDType handlers 
     */
    protected Map<String, INameIDFormatHandler> _mFormatHandlers;

    /**
     * Default format; either configured using the nameid@default attribute,
     * or otherwise the first element from the configuration
     */
    private String _sDefaultFormat;

    
    /**
     * Creates the object.
     *
     * @param oConfigManager The configuration manager containing the configuration.
     * @param elConfig The configuration section for this object.
     * @param oCryptoManager Crypto manager
     * @param oTGTAliasStore TGT alias store
     * @throws OAException If object could not be created.
     */
    public NameIDFormatter(IConfigurationManager oConfigManager,
        Element elConfig, CryptoManager oCryptoManager, ITGTAliasStore oTGTAliasStore) 
        throws OAException
    {
        try
        {
            _oTGTAliasStore = oTGTAliasStore;
            _oCryptoManager = oCryptoManager;

            // Establish which formats are supported, and by which implementation
            // they are handled; the supported format are the keys of the map
            _mFormatHandlers = readFormatConfig(oConfigManager, elConfig);
        }
        catch (OAException e) {
        	// Rethrow the exception:
            throw e;
        } catch (Exception e) {
            _oLogger.error("Exception when creating object instance: ", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Creates the object with empty sets and defaults.
     *
     * @param cryptoManager Crypto manager
     * @param tgtAliasStore TGT alias store
     * @throws OAException If object could not be created.
     */
    public NameIDFormatter(CryptoManager cryptoManager, ITGTAliasStore tgtAliasStore) 
        throws OAException
    {
        try
        {
            _oTGTAliasStore = tgtAliasStore;
            _oCryptoManager = cryptoManager;

            // Empty defaults:
            _mFormatHandlers = new HashMap<String, INameIDFormatHandler>();
            _sDefaultFormat = null;
        }
        catch (Exception e) {
            _oLogger.error("Exception when creating default object instance: ", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    
    /**
     * Returns the crypto manager used by the NameIDFormatter
     */
    public CryptoManager getCryptoManager() {
    	return _oCryptoManager;
    }
    
    
    /**
     * Returns the default configured NameID Format.
     * 
     * @return The default NameID Format URI.
     */
    public String getDefault() {
        return _sDefaultFormat;
    }
    
    
    /**
     * Verifies whether the supplied NameIDFormat is supported.
     * 
     * @param nameIDFormat Name ID Format to verify
     * @return TRUE if supplied Name ID Format is supported
     */
    public boolean isSupported(String nameIDFormat) {
        return _mFormatHandlers.keySet().contains(nameIDFormat);
    }
    
    
    /**
     * Formats the User id to the requested Name ID Format.
     *
     * @param oUser the user
     * @param sTGTID The users tgt or NULL if not available.
     * @param sNameIDFormat The target format.
     * @param sEntityID Requestor or IDP ID.
     * @return The formatted user ID.
     * @throws OAException if user ID could not be formatted.
     */
    public String format(IUser oUser, String sNameIDFormat, String sEntityID, String sTGTID) 
        throws OAException
    {
        if (oUser == null)
            throw new IllegalArgumentException("Supplied user is empty");
        
        if (sEntityID == null)
            throw new IllegalArgumentException("Supplied Entity ID is empty");

        if (sNameIDFormat == null)
            throw new IllegalArgumentException("Supplied NameIDFormat is empty");
        
    	INameIDFormatHandler oNIFH = _mFormatHandlers.get(sNameIDFormat);
    	if (oNIFH == null) {
    		_oLogger.error("Request for formatting unsupported NameIDFormat: '"+sNameIDFormat+"'");
    		throw new OAException(SystemErrors.ERROR_INTERNAL);
    	}

    	String sNameID = null;
        try
        {
        	ISession oSession = null;	// how to get session here....

        	String sType = mFormatToType.get(sNameIDFormat);
        	
    		if (sType != null) {
    			sNameID = generate(sNameIDFormat, oUser, sEntityID, sTGTID, oSession);
    		} else {
    			_oLogger.error("Unsupported NameID Format requested: " + sNameIDFormat);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
    		}
    		
        } 
        catch (OAException e) {
            throw e;
        }
        catch (Exception e) {
            _oLogger.fatal("Could not generate name ID format", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return sNameID;
    }

    
    /**
     * Verifies if the nameid in a request message is equal to the nameid 
     * generated by the format methode.
     * 
     * @param sNameIDFormat The nameID format supplied in the request message.
     * @param sNameID The NameID supplied in the request message.
     * @param sEntityID The entity id.
     * @param tgtID The user TGT ID.
     * @return TRUE if the supplied nameid is valid.
     * @throws OAException If an internal error occurred.
     */
    public boolean verify(String sNameIDFormat, String sNameID, 
        String sEntityID, String tgtID) throws OAException
    {
        try
        {
        	String sType = mFormatToType.get(sNameIDFormat);
        	if (sType == null) {
                _oLogger.debug("Unsupported NameID Format requested: " + sNameIDFormat);
                return false;
        	}
        	
        	String sAlias = _oTGTAliasStore.getAlias(sType, sEntityID, tgtID);
        	if (sAlias == null) {
        		return false;	// alias does not exist
        	}
        	
        	return sAlias.equals(sNameID);
        }
        catch (OAException e) {
            throw e;
        }
        catch (Exception e) {
            _oLogger.fatal("Could not verify Name ID", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns the name id in the correct format for the specific entity.  
     * @param sNameIDFormat The format of the user id.
     * @param sEntityID The entity ID.
     * @param tgtID The tgt ID of the user.
     * @return The name id in the requested format or NULL if not available.
     * @throws OAException If an internal error ocurred.
     * @since 1.2
     */
    public String resolve(String sNameIDFormat, String sEntityID, String tgtID) 
        throws OAException
    {
        try
        {
        	String sType = mFormatToType.get(sNameIDFormat);
        	if (sType == null) {
                _oLogger.debug("Unsupported NameID Format requested: " + sNameIDFormat);
                return null;
        	}
        	
        	return _oTGTAliasStore.getAlias(sType, sEntityID, tgtID);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _oLogger.fatal("Could not resolve Name ID", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }     
    }
    
    
    /**
     * Verifies if an NameID already exists as TGT alias.
     * @param sNameIDFormat The format of the user id.
     * @param sEntityID The entity ID.
     * @param sNameID The NameID (TGT alias) to be checked.
     * @return TRUE if the supplied NameID is a TGT alias.
     * @throws OAException If an internal error ocurred.
     * @since 1.2
     */
    public boolean exists(String sNameIDFormat, String sEntityID, String sNameID) 
        throws OAException
    {
        try
        {
        	String sType = mFormatToType.get(sNameIDFormat);
        	if (sType == null) {
                _oLogger.debug("Unsupported NameID Format requested: " + sNameIDFormat);
                return false;
        	}
        	
        	return _oTGTAliasStore.isAlias(sType, sEntityID, sNameID);
        }
        catch (OAException e) {
            throw e;
        }
        catch (Exception e) {
            _oLogger.error("Unable to verify alias '"+sNameID+"'for '"+sEntityID+
            		"' and type '"+sNameIDFormat);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }     
    }

    
    /**
     * Resolves the TGT ID for a TGT Alias.
     * 
     * @param sNameIDFormat The format of the user id.
     * @param sEntityID The entity ID.
     * @param sNameID The NameID (TGT alias) to be checked.
     * @return The TGT ID or NULL if not available.
     * @throws OAException If an internal error ocurred.
     * @since 1.2
     */
    public String resolveTGTID(String sNameIDFormat, String sEntityID, String sNameID) 
        throws OAException
    {
        try
        {
        	String sType = mFormatToType.get(sNameIDFormat);
        	if (sType == null) {
                _oLogger.debug("Unsupported NameID Format requested: " + sNameIDFormat);
                return null;
        	}
        	
        	return _oTGTAliasStore.getTGTID(sType, sEntityID, sNameID);
        }
        catch (OAException e) {
            throw e;
        }
        catch (Exception e) {
            _oLogger.error("Unable to find TGT with alias '"+sNameID+"'for '"+sEntityID+
            		"' and type '"+sNameIDFormat);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }     
    }

    
    /**
     * Store the supplied NameID as TGT alias.
     *
     * @param sTGTID The TGT ID for which the alias must be stored
     * @param sNameIDFormat The Alias type
     * @param sEntityID The Entity ID
     * @param sNameID The TGT Alias
     * @throws OAException If NameIDFormat is unknown
     * @since 1.2.1
     */
    public void store(String sTGTID, String sNameIDFormat, String sEntityID, 
        String sNameID) throws OAException
    {
        try
        {
        	String sType = mFormatToType.get(sNameIDFormat);
        	if (sType == null) {
                _oLogger.debug("Unsupported NameID Format requested: " + sNameIDFormat);
                return;
        	}
        	
        	_oTGTAliasStore.putAlias(sType, sEntityID, sTGTID, sNameID);
        	
        }
        catch (OAException e) {
            throw e;
        }
        catch (Exception e) {
            _oLogger.error("Unable to store alias '"+sNameID+"'for '"+sEntityID+
            		"' and type '"+sNameIDFormat+" with TGT '"+sTGTID+"'");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    
    /**
     * Remove the supplied NameID as TGT alias.
     *
     * @param sNameIDFormat The Alias type
     * @param sEntityID The Entity ID
     * @param sNameID The TGT Alias
     * @throws OAException If NameIDFormat is unknown
     * @since 1.2.1
     */
    public void remove(String sNameIDFormat, String sEntityID, 
        String sNameID) throws OAException
    {
        try
        {
        	String sType = mFormatToType.get(sNameIDFormat);
        	if (sType == null) {
                _oLogger.debug("Unsupported NameID Format requested: " + sNameIDFormat);
                return;
        	}
        	
        	_oTGTAliasStore.removeAlias(sType, sEntityID, sNameID);
        }
        catch (OAException e) {
            throw e;
        }
        catch (Exception e) {
            _oLogger.error("Unable to remove alias '"+sNameID+"'for '"+sEntityID+
            		"' and type '"+sNameIDFormat);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    
    private String generate(String sType, IUser oUser, String sEntityID, String sTGTID,
    		ISession oSession)
    	throws OAException
    {
    	INameIDFormatHandler oHandler = _mFormatHandlers.get(sType);
    	
    	String sDomain = sEntityID;
    	String sAlias = null;
    	String sAliasType = mFormatToType.get(sType);    	
    	
    	// If the NameID format is domain scoped, check if there is a value to re-use
    	if (oHandler.isDomainScoped()) {
    		sDomain = oHandler.getDomain(oUser, sEntityID);
    		
    		// Find the alias in the domain:
    		if (sTGTID != null) {
    			sAlias = _oTGTAliasStore.getAlias(sAliasType, sDomain, sTGTID);
    		}
    	}
    	
    	// No Identifier to re-use, generate new one
    	// Support regeneration a couple of times to ensure that the identifier 
    	//   should be unique within the domain
    	if (sAlias == null) {
    		int i=0; // loop protection
    		do {
    			sAlias = oHandler.format(oUser, sDomain, sTGTID, oSession);
    			i++;
    		} while (i<100 && 
    				(oHandler.isDomainUnique() && _oTGTAliasStore.isAlias(sAliasType, sDomain, sAlias))
    				);
    		
    		if (i >= 100) {
    			_oLogger.error("Giving up; can not create unique NameID value within context of '"+sDomain+
    					"': '"+sAlias+"'");
    			throw new OAException(SystemErrors.ERROR_INTERNAL);
    		}
    	} else {
    		// Alias already generated; call reformat on Formatter to
    		// ensure consistent attribute-state
    		oHandler.reformat(oUser, sEntityID, sTGTID, oSession);
    	}
    	
    	// Store established NameID value in domain context for later re-use:
    	if (oHandler.isDomainScoped() && sTGTID != null) {
    		_oTGTAliasStore.putAlias(sAliasType, sDomain, sTGTID, sAlias);
    	}
    	
    	return sAlias;
    }
    
    
    private Map<String, INameIDFormatHandler> readFormatConfig(IConfigurationManager oConfigManager,
    	Element elConfig) throws OAException
    {
    	Map<String, INameIDFormatHandler> oFormatHandlers = new HashMap<String, INameIDFormatHandler>();
    	
    	String sFirstType = null;
    	
    	Element elFormat = oConfigManager.getSection(elConfig, EL_FORMAT);
    	while (elFormat != null) {
    		String sType = oConfigManager.getParam(elFormat, EL_ID);
    		if (sType == null) {
    			_oLogger.error("No @"+EL_ID+" specified with NameID format");
    			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
    		}
    		
    		// Remember the first configured type, as default type when no default was specified:
    		if (sFirstType == null) sFirstType = sType;
    		
    		String sClassname = oConfigManager.getParam(elFormat,  EL_CLASS);
    		if (sClassname == null) {
    			sClassname = mFormatDefaultClass.get(sType);
    		}
    		
    		if (sClassname == null) {
    			_oLogger.error("No implementation could be found to handle NameID format type '"+
    					sType+"'");
    			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
    		}
    		
    		// Create and initialize the handler:
    		INameIDFormatHandler oHandler = createHandler(sClassname);
    		oHandler.init(oConfigManager, elFormat, this);
    		
    		// Add as supported type:
    		oFormatHandlers.put(sType, oHandler);
    		
    		_oLogger.info("NameIDFormat type '"+sType+"' support added through "+sClassname);
    		
    		elFormat = oConfigManager.getNextSection(elFormat);
    	}
    	
    	
    	// Check for valid default type:
    	_sDefaultFormat = null;
    	
    	String sDefaultType = oConfigManager.getParam(elConfig, EL_ATTR_DEFAULT);
    	if (sDefaultType != null) {
    		if (oFormatHandlers.keySet().contains(sDefaultType)) {
    			_sDefaultFormat = sDefaultType;
    		} else {
    			_oLogger.error("The configured default NameID type is not supported: '"+
    					sDefaultType+"'");
    			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
    		}
    	}

    	// If no handler was configured, use the first configured element 
    	if (_sDefaultFormat == null) {
    		_oLogger.info("Using '"+sFirstType+"' as default NameID Format type");
    		_sDefaultFormat = sFirstType;
    	}
    	
    	return oFormatHandlers;
    }
    
    
    private INameIDFormatHandler createHandler(String sClass)
    	throws OAException
    {
    	INameIDFormatHandler oHandler = null;
    	
    	Class<?> oClass = null;
        try {
            oClass = Class.forName(sClass);
        } catch (Exception e) {
            _oLogger.error("No 'class' found with name: " + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        try {
        	oHandler = (INameIDFormatHandler) oClass.newInstance();
        } catch (Exception e) {
            _oLogger.error("Could not create an 'INameIDFormatHandler' instance of class with name '"+
            	sClass + "'", e); 
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        return oHandler;
    }
    
    
    /**
     * Const Initializer for default implementations.
     * These are also all the NameIDQualifiers that are supported with default implementations
     * See saml2-core specification section 8.3 for specified formats
     * @return Map with default implementations for specified NameID formats
     */
    private static Map<String, String> createFormatDefaultClassMap() {
    	Map<String, String> oMap = new HashMap<String, String>();
        oMap.put(NameIDType.UNSPECIFIED, "org.asimba.util.saml2.nameid.handler.DefaultUnspecifiedFormatHandler"); //+
        oMap.put(NameIDType.EMAIL, "org.asimba.util.saml2.nameid.handler.AttributeFormatHandler"); //+
        oMap.put(NameIDType.X509_SUBJECT, "org.asimba.util.saml2.nameid.handler.DefaultX509SubjectNameHandler"); //_
        oMap.put(NameIDType.WIN_DOMAIN_QUALIFIED, "org.asimba.util.saml2.nameid.handler.DefaultWindowsDomainQualifiedNameHandler"); //_
        oMap.put(NameIDType.KERBEROS, "org.asimba.util.saml2.nameid.handler.DefaultKerberosPrincipalNameHandler"); //_
        oMap.put(NameIDType.ENTITY, "org.asimba.util.saml2.nameid.handler.DefaultEntityIdentifierHandler"); //_
        oMap.put(NameIDType.PERSISTENT, "org.asimba.util.saml2.nameid.handler.DefaultPersistentFormatHandler");	//+
        oMap.put(NameIDType.TRANSIENT, "org.asimba.util.saml2.nameid.handler.DefaultTransientFormatHandler"); //+
        
        return Collections.unmodifiableMap(oMap);
    }
    

    /**
     * Const Initializer for mapping of NameIDFormat type to TGT Alias Type-attribute (i.e. database table column)
     * @return Map with mappings
     */
    private static Map<String, String> createFormatToTypeMap() {
    	Map<String, String> oMap = new HashMap<String, String>();
    	oMap.put(NameIDType.TRANSIENT, "transient_user_id");
    	oMap.put(NameIDType.PERSISTENT, "persistent_user_id");
    	oMap.put(NameIDType.UNSPECIFIED, "unspecified11_user_id");
    	oMap.put("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified", "unspecified20_user_id");
    	oMap.put(NameIDType.EMAIL, "email_user_id");
    	return Collections.unmodifiableMap(oMap);
    }

}
