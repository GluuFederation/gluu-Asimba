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

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.NameIDType;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;

/**
 * NameID Formatter.
 *
 * @author JRE
 * @author MHO
 * @author Alfa & Ariss
 */
public class NameIDFormatter
{
    /** Not standard SAML 2.0 Unspecified URI: urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified */
    public final static String SAML20_UNSPECIFIED = 
        "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
    /** Default transient length: 256 */
    public final static int DEFAULT_TRANSIENT_LENGTH = 256;
    
    /** Type: TGT_ALIAS */
    public final static String TYPE_ALIAS_TGT = "session_index";
    /** Type: TRANSIENT_USER_ID */
    public final static String TYPE_ALIAS_TRANSIENT_UID = "transient_user_id";
    /** Type: PERSISTENT_USER_ID */
    public final static String TYPE_ALIAS_PERSISTENT_UID = "persistent_user_id";
    /** Type: unspecified UID for SAML1.1 */
    public final static String TYPE_ALIAS_UNSPECIFIED11_UID = "unspecified11_user_id";
    /** Type: unspecified UID for SAML2.0 */
    public final static String TYPE_ALIAS_UNSPECIFIED20_UID = "unspecified20_user_id";
    /** Type: Email UID */
    public final static String TYPE_ALIAS_EMAIL_UID = "email_user_id";
    
    private final static char[] TRANSIENT_CHARS = {
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        '1','2','3','4','5','6','7','8','9','0'};
    
    private Log _logger;
    private CryptoManager _cryptoManager;
    private SecureRandom _secureRandom;
    private List<String> _listFormats;
    private String _sDefaultFormat;
    private boolean _bOpaqueEnabled;
    private String _sOpaqueSalt;
    private int _iTransientLength;
    private ITGTAliasStore _tgtAliasStore;
    private Map<String, String> _mapAttributeNames;
    
    /**
     * Creates the object.
     *
     * @param configurationManager The configuration manager contianing the configuration.
     * @param config The configuration section for this object.
     * @param cryptoManager Crypto manager
     * @param tgtAliasStore TGT alias store
     * @throws OAException If object could not be created.
     */
    public NameIDFormatter(IConfigurationManager configurationManager,
        Element config, CryptoManager cryptoManager, ITGTAliasStore tgtAliasStore) 
        throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(NameIDFormatter.class);
            
            _bOpaqueEnabled = false;
            _sOpaqueSalt = null;
            _mapAttributeNames = new HashMap<String, String>();
            
            _tgtAliasStore = tgtAliasStore;
            _cryptoManager = cryptoManager;
            _secureRandom = _cryptoManager.getSecureRandom();

            _listFormats = readConfig(configurationManager, config);
            
            _sDefaultFormat = configurationManager.getParam(config, "default");
            if (_sDefaultFormat != null)
            {
                if (!_listFormats.contains(_sDefaultFormat))
                {
                    _logger.error("Invalid 'default' NameID configured: " + _sDefaultFormat);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _logger.info("Using default NameID Format: " + _sDefaultFormat);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not create object", e);
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
            _logger = LogFactory.getLog(NameIDFormatter.class);
            
            _bOpaqueEnabled = false;
            _sOpaqueSalt = null;
            _mapAttributeNames = new HashMap<String, String>();
            
            _tgtAliasStore = tgtAliasStore;
            _cryptoManager = cryptoManager;
            _secureRandom = _cryptoManager.getSecureRandom();

            _listFormats = new Vector<String>();
            
            _sDefaultFormat = null;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not create object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns the default configured NameID Format.
     * 
     * @return The default NameID Format URI.
     */
    public String getDefault()
    {
        return _sDefaultFormat;
    }
    
    /**
     * Verifies if the supplied Name ID Format is supported.
     * 
     * @param nameIDFormat Name ID Format to verify
     * @return TRUE if supplied Name ID Format is supported
     */
    public boolean isSupported(String nameIDFormat)
    {
        return _listFormats.contains(nameIDFormat);
    }
    
    /**
     * Formats the User id to the requested Name ID Format.
     *
     * @param user the user
     * @param tgtID The users tgt or NULL if not available.
     * @param nameIDFormat The target format.
     * @param sEntityID Requestor or IDP ID.
     * @return The formatted user ID.
     * @throws OAException if user ID could not be formatted.
     */
    public String format(IUser user, String nameIDFormat, String sEntityID, String tgtID) 
        throws OAException
    {
        if (user == null)
            throw new IllegalArgumentException("Supplied user is empty");
        
        if (sEntityID == null)
            throw new IllegalArgumentException("Supplied Entity ID is empty");

        if (nameIDFormat == null)
            throw new IllegalArgumentException("Supplied NameIDFormat is empty");
        
        String nameID = null;
        try
        {
            if (nameIDFormat.equals(NameIDType.TRANSIENT))
            {
                nameID = generateTransient(tgtID, sEntityID);
            }
            else if (nameIDFormat.equals(NameIDType.PERSISTENT))
            {
                nameID = generatePersistent(TYPE_ALIAS_PERSISTENT_UID, tgtID, 
                    sEntityID, user, user.getAttributes());
            }
            else if (nameIDFormat.equals(NameIDType.UNSPECIFIED))
            {
                nameID = generatePersistent(TYPE_ALIAS_UNSPECIFIED11_UID, 
                    tgtID, sEntityID, user, user.getAttributes());
            }
            else if (nameIDFormat.equals(SAML20_UNSPECIFIED))
            {
                nameID = generatePersistent(TYPE_ALIAS_UNSPECIFIED20_UID, 
                    tgtID, sEntityID, user, user.getAttributes());
            }
            else if (nameIDFormat.equals(NameIDType.EMAIL))
            {
                nameID = generatePersistent(TYPE_ALIAS_EMAIL_UID, 
                    tgtID, sEntityID, user, user.getAttributes());
            }
            else
            {
                _logger.error("Unsupported NameID Format requested: " + nameIDFormat);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not generate name ID format", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return nameID;
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
            if (sNameIDFormat.equals(NameIDType.PERSISTENT))
            {
                String sAlias = _tgtAliasStore.getAlias(TYPE_ALIAS_PERSISTENT_UID, 
                    sEntityID, tgtID);
                if (sAlias != null)
                    return sAlias.equals(sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.TRANSIENT))
            {
                String sAlias = _tgtAliasStore.getAlias(TYPE_ALIAS_TRANSIENT_UID, 
                    sEntityID, tgtID);
                if (sAlias != null)
                    return sAlias.equals(sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.EMAIL))
            {
                String sAlias = _tgtAliasStore.getAlias(TYPE_ALIAS_EMAIL_UID, 
                    sEntityID, tgtID);
                if (sAlias != null)
                    return sAlias.equals(sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.UNSPECIFIED)) 
            {
                String sAlias = _tgtAliasStore.getAlias(TYPE_ALIAS_UNSPECIFIED11_UID, 
                    sEntityID, tgtID);
                if (sAlias != null)
                    return sAlias.equals(sNameID);
            }
            else if (sNameIDFormat.equals(SAML20_UNSPECIFIED))
            {
                String sAlias = _tgtAliasStore.getAlias(TYPE_ALIAS_UNSPECIFIED20_UID, 
                    sEntityID, tgtID);
                if (sAlias != null)
                    return sAlias.equals(sNameID);
            }
            else
            {
                _logger.debug("Unsupported NameID Format requested: " + 
                    sNameIDFormat);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not verify Name ID", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return false;
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
            if (sNameIDFormat.equals(NameIDType.PERSISTENT))
            {
                return _tgtAliasStore.getAlias(TYPE_ALIAS_PERSISTENT_UID, 
                    sEntityID, tgtID);
            }
            else if (sNameIDFormat.equals(NameIDType.TRANSIENT))
            {
                return _tgtAliasStore.getAlias(TYPE_ALIAS_TRANSIENT_UID, 
                    sEntityID, tgtID);
            }
            else if (sNameIDFormat.equals(NameIDType.EMAIL))
            {
                return _tgtAliasStore.getAlias(TYPE_ALIAS_EMAIL_UID, 
                    sEntityID, tgtID);
            }
            else if (sNameIDFormat.equals(NameIDType.UNSPECIFIED)) 
            {
                return _tgtAliasStore.getAlias(TYPE_ALIAS_UNSPECIFIED11_UID, 
                    sEntityID, tgtID);
            }
            else if (sNameIDFormat.equals(SAML20_UNSPECIFIED))
            {
                return _tgtAliasStore.getAlias(TYPE_ALIAS_UNSPECIFIED20_UID, 
                    sEntityID, tgtID);
            }
            else
            {
                _logger.debug("Unsupported NameID Format requested: " + 
                    sNameIDFormat);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not resolve Name ID", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }     
        return null;
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
            if (sNameIDFormat.equals(NameIDType.PERSISTENT))
            {
                return _tgtAliasStore.isAlias(TYPE_ALIAS_PERSISTENT_UID, 
                    sEntityID, sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.TRANSIENT))
            {
                return _tgtAliasStore.isAlias(TYPE_ALIAS_TRANSIENT_UID, 
                    sEntityID, sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.EMAIL))
            {
                return _tgtAliasStore.isAlias(TYPE_ALIAS_EMAIL_UID, 
                    sEntityID, sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.UNSPECIFIED)) 
            {
                return _tgtAliasStore.isAlias(TYPE_ALIAS_UNSPECIFIED11_UID, 
                    sEntityID, sNameID);
            }
            else if (sNameIDFormat.equals(SAML20_UNSPECIFIED))
            {
                return _tgtAliasStore.isAlias(TYPE_ALIAS_UNSPECIFIED20_UID, 
                    sEntityID, sNameID);
            }
            else
            {
                _logger.debug("Unsupported NameID Format supplied for exist check: " + 
                    sNameIDFormat);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer();
            sbError.append("Could not check if alias for entityID '");
            sbError.append(sEntityID);
            sbError.append("' exists for supplied NameIDFormat '");
            sbError.append(sNameIDFormat);
            sbError.append("' for NameID: ");
            sbError.append(sNameID);
            _logger.fatal(sbError.toString(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }     
        return false;
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
            if (sNameIDFormat.equals(NameIDType.PERSISTENT))
            {
                return _tgtAliasStore.getTGTID(TYPE_ALIAS_PERSISTENT_UID, 
                    sEntityID, sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.TRANSIENT))
            {
                return _tgtAliasStore.getTGTID(TYPE_ALIAS_TRANSIENT_UID, 
                    sEntityID, sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.EMAIL))
            {
                return _tgtAliasStore.getTGTID(TYPE_ALIAS_EMAIL_UID, 
                    sEntityID, sNameID);
            }
            else if (sNameIDFormat.equals(NameIDType.UNSPECIFIED)) 
            {
                return _tgtAliasStore.getTGTID(TYPE_ALIAS_UNSPECIFIED11_UID, 
                    sEntityID, sNameID);
            }
            else if (sNameIDFormat.equals(SAML20_UNSPECIFIED))
            {
                return _tgtAliasStore.getTGTID(TYPE_ALIAS_UNSPECIFIED20_UID, 
                    sEntityID, sNameID);
            }
            else
            {
                _logger.debug("Unsupported NameID Format supplied for resolving TGT ID: " + 
                    sNameIDFormat);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer();
            sbError.append("Could not resolve TGT ID for alias '");
            sbError.append(sNameID);
            sbError.append("' for entityID '");
            sbError.append(sEntityID);
            sbError.append("' with NameIDFormat '");
            sbError.append(sNameIDFormat);
            _logger.fatal(sbError.toString(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }     
        return null;
    }
    
    private String generatePersistent(String type, String tgtID, 
        String sEntityID, IUser user, IAttributes attributes) throws OAException
    {
        String sPersistent = null;
        String sAttributeName = _mapAttributeNames.get(type);
        try
        {
            if (tgtID != null)
            {
                sPersistent = _tgtAliasStore.getAlias(type, 
                    sEntityID, tgtID);
            }

            if (sPersistent == null)
            {
                //generate persistent id
                if (sAttributeName != null)
                {
                    if (attributes == null)
                    {
                        StringBuffer sbError = new StringBuffer("User '");
                        sbError.append(user.getID());
                        sbError.append("' does not have the required user attribute: ");
                        sbError.append(sAttributeName);
                        
                        _logger.error(sbError.toString());
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                    if (!attributes.contains(sAttributeName))
                    {
                        StringBuffer sbError = new StringBuffer("User '");
                        sbError.append(user.getID());
                        sbError.append("' does not have the required user attribute: ");
                        sbError.append(sAttributeName);
                        
                        _logger.error(sbError.toString());
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                    
                    sPersistent = (String)attributes.get(sAttributeName);
                    //DD remove the attribute when it is used as Persistent Alias
                    attributes.remove(sAttributeName);
                }
                else
                    sPersistent = user.getID();
                
                if (_bOpaqueEnabled && type.equals(TYPE_ALIAS_PERSISTENT_UID))
                    sPersistent = generateOpaqueNameID(sPersistent);
                
                if (tgtID != null)
                {
                    _tgtAliasStore.putAlias(type, sEntityID, tgtID, sPersistent);
                }
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could generate user id for user with tgt: " 
                + tgtID, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return sPersistent;
    }
        
    private String generateOpaqueNameID(String userID) throws OAException
    {
        try
        {
            if (_sOpaqueSalt != null)
                userID = userID + _sOpaqueSalt;
            
            // the returned user ID must contain an opaque value 
            MessageDigest oMessageDigest = _cryptoManager.getMessageDigest();
            try
            {
                oMessageDigest.update(userID.getBytes(SAML2Constants.CHARSET));
                char[] ca = Hex.encodeHex(oMessageDigest.digest());
                userID = new String(ca);
            }
            catch (Exception e)
            {
                _logger.warn("Unable to generate SHA1 hash from user ID: " 
                    + userID);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not generate opaque user id", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return userID;
    }  
    
    private String generateTransient(String tgtID, String sEntityID) 
        throws OAException
    {
        String sTransient = null;
        try
        {
            if (tgtID != null)
            {
                sTransient = _tgtAliasStore.getAlias(TYPE_ALIAS_TRANSIENT_UID, 
                    sEntityID, tgtID);
            }
            
            if (sTransient == null)
            {
                //generate new transient user id
                do
                {
                    sTransient = generateRandom(_iTransientLength);
                }
                while(_tgtAliasStore.isAlias(TYPE_ALIAS_TRANSIENT_UID, sEntityID, 
                    sTransient));
                
                if (tgtID != null)
                {
                    _tgtAliasStore.putAlias(TYPE_ALIAS_TRANSIENT_UID, sEntityID, 
                        tgtID, sTransient);
                }
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could generate transient for user with tgt: " 
                + tgtID, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return sTransient;
    }
    
    private String generateRandom(int iLength)
    {
        StringBuffer sbGenerated = new StringBuffer();
        for (int i = 0; i < iLength; i++)
        {
            int iPosition = _secureRandom.nextInt(TRANSIENT_CHARS.length);
            sbGenerated.append(TRANSIENT_CHARS[iPosition]);
        }
        return sbGenerated.toString();
    }
    
    private List<String> readConfig(IConfigurationManager configurationManager,
        Element config) throws OAException
    {
        List<String> listFormats = new Vector<String>();
        try
        {
            Element eFormat = configurationManager.getSection(config, "format");
            while (eFormat != null)
            {
                String id = configurationManager.getParam(eFormat, "id");
                if (id == null)
                {
                    _logger.error("No 'id' item found in 'format' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (listFormats.contains(id))
                {
                    _logger.error("Configured NameID Format id is not unique: " + id);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (id.equals(NameIDType.PERSISTENT))
                {
                    readConfigPersistent(configurationManager, eFormat);
                }
                else if (id.equals(NameIDType.TRANSIENT))
                {
                    readConfigTransient(configurationManager, eFormat);
                }
                else if (id.equals(NameIDType.EMAIL))
                {
                    readAttributeConfig(configurationManager, eFormat, TYPE_ALIAS_EMAIL_UID);
                }
                else if (id.equals(NameIDType.UNSPECIFIED))
                {
                    readAttributeConfig(configurationManager, eFormat, TYPE_ALIAS_UNSPECIFIED11_UID);
                }
                else if (id.equals(SAML20_UNSPECIFIED))
                {//DD Also supporting urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified in NameIDPolicy
                    readAttributeConfig(configurationManager, eFormat, TYPE_ALIAS_UNSPECIFIED20_UID);
                }                
                else
                {
                    _logger.error("Unsupported NameID Format id configured: " + id);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                listFormats.add(id);
                
                eFormat = configurationManager.getNextSection(eFormat);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not read config", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return listFormats;
    }
    
    private void readConfigTransient(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        try
        {
            String sLength = configurationManager.getParam(config, "length");
            if (sLength != null)
            {
                try
                {
                    _iTransientLength = Integer.parseInt(sLength);
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Configured 'length' item doesn't contain a number value: " + sLength);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            else
                _iTransientLength = DEFAULT_TRANSIENT_LENGTH;
            
            _logger.info("Using transient length: " + _iTransientLength);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not read transient config", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    private void readConfigPersistent(IConfigurationManager configurationManager,
        Element config) throws OAException
    {
        try
        {
            readAttributeConfig(configurationManager, config, TYPE_ALIAS_PERSISTENT_UID);
            
            Element eOpaque = configurationManager.getSection(config, "opaque");
            if (eOpaque != null)
            {
                String enabled = configurationManager.getParam(eOpaque, "enabled");
                if (enabled != null)
                {
                    if (enabled.equalsIgnoreCase("TRUE"))
                        _bOpaqueEnabled = true;
                    else if (!enabled.equalsIgnoreCase("FALSE"))
                    {
                        _logger.error("Invalid 'enabled' item found in 'opaque' section in configuration (must be true or false): "
                            + enabled);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                
                if (_bOpaqueEnabled)
                {
                    _logger.info("Opaque enabled");
                    
                    _sOpaqueSalt = configurationManager.getParam(eOpaque, "salt");
                    if (_sOpaqueSalt == null)
                        _logger.info("No opaque 'salt' configured");
                    else
                        _logger.info("Using configured opaque 'salt': " + _sOpaqueSalt);
                }
                else
                    _logger.warn("Opaque disabled");
            }
            
            if (!_mapAttributeNames.containsKey(TYPE_ALIAS_PERSISTENT_UID) && !_bOpaqueEnabled)
            {
                _logger.error("Invalid Persistent configuration: No attribute configured and opaque is disabled");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not read persistent config", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void readAttributeConfig(IConfigurationManager configurationManager,
        Element config, String type) throws OAException
    {
        try
        {
            String sAttribute = null;
    
            Element eAttribute = configurationManager.getSection(config, "attribute");
            if (eAttribute != null)
            {
                sAttribute = configurationManager.getParam(eAttribute, "name");
                if (sAttribute == null)
                {
                    _logger.error("No 'name' item found in 'attribute' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _mapAttributeNames.put(type, sAttribute);
                _logger.info("Using '" + type + "' attribute: " + sAttribute);
            }
            
            if (sAttribute == null)
                _logger.info("No optional '" + type + "' attribute found in configuration");
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not read config for: " + type, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
