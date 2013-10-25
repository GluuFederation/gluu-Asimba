/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2011 Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.remote.saml2.idp.storage.config;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.management.MdMgrManager;
import org.asimba.util.saml2.metadata.provider.management.MetadataProviderManagerUtil;
import org.asimba.utility.filesystem.PathTranslator;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;

/**
 * Uses the XML configuration file as organization storage for SAML2IDPs
 * 
 * Configuration like:
 * <storage id="[id-value]" class="[...IDPConfigStorage]" registerWithEngine="[true/false]">
 *   <mp_manager id="[id-value]" primary="[true/false]" />
 *   <idp ...>
 *   	[idp-configuration]
 *   </idp>
 * </storage>
 * 
 * #signing : optional attribute to indicate whether default-signing should be enabled 
 * 		for a SAML2Requestor
 * 
 * mp_manager : optional configuration for metadataprovider manager; if the configuration is
 * 		not provided, a MetadataProviderManager is used by the name of the Profile; if it is
 * 		created, it will also be removed upon destroy() of the SAMLRequestors
 * #id : attribute that indicates the id of the MetadataProviderManager
 * 		that is responsible for managing the MetadataProvider for a SAML2Requestor; when
 * 		mpmanaged_id is not set, the profileId is used to identify the MetadataProviderManager
 * #primary : if true, and if the manager was instantiated, the manager will also be destroyed
 * 		when destroy() of the SAML2Requestors is called. Defaults to false. 
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public class IDPConfigStorage extends AbstractConfigurationStorage 
{
	/** Configuration elements */
	public static final String EL_MPMANAGER = "mp_manager";

	/** Local logger instance */
	private static Log _oLogger = LogFactory.getLog(IDPConfigStorage.class);
	
    private final static String DEFAULT_ID = "saml2";
    
    /** Id of the Storage */
    protected String _sId;
    
    /** Id of the MetadataProviderManager that manages metadata for the SAML2IDPs that are
     * created by this Storage; configurable; defaults to the Id of the Storage (_sId) */
    protected String _sMPMId;
    protected boolean _bOwnMPM;
    
    
    private Map<SourceID, SAML2IDP> _mapIDPsOnSourceID;
        
    /**
     * Creates the storage.
     */
    public IDPConfigStorage()
    {
        super();
        _mapIDPsOnSourceID = new Hashtable<SourceID, SAML2IDP>();
    }

    /**
     * @see com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configManager, Element config)
        throws OAException
    {
        _sId = configManager.getParam(config, "id");
        if (_sId == null)
        {
            _oLogger.info("No optional 'id' item for storage configured, using default");
            _sId = DEFAULT_ID;
        }

        // Establish MetadataProviderManager Id that refers to existing IMetadataProviderManager
        Element elMPManager = configManager.getSection(config, EL_MPMANAGER);
        if (elMPManager == null) {
        	_oLogger.info("Using MetadataProviderManager Id from IDPStorage@id: '"+_sId+"'");
        	_sMPMId = _sId;
        } else {
        	_sMPMId = configManager.getParam(elMPManager, "id");
        	if (_sMPMId == null) {
        		_oLogger.error("Missing @id attribute for '"+EL_MPMANAGER+"' configuration");
        		throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        	}
        	_oLogger.info("Using MetadataProviderManager Id from configuration: '"+_sMPMId+"'");
        }
        
        // Make sure the MetadataProviderManager exists
        boolean bCreated = MetadataProviderManagerUtil.establishMPM(_sMPMId, configManager, elMPManager);
        
        if (elMPManager == null) {
        	_bOwnMPM = bCreated;
        } else {
        	String sPrimary = configManager.getParam(elMPManager, "primary");
        	if (sPrimary == null ) {
        		_bOwnMPM = bCreated;	// default: own it when it was created by us
        	} else {
        		if ("false".equalsIgnoreCase(sPrimary)) {
        			_bOwnMPM = false;
        		} else if ("true".equalsIgnoreCase(sPrimary)) {
        			_bOwnMPM = true;
        		} else {
        			_oLogger.error("Invalid value for '@primary': '"+sPrimary+"'");
        			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        		}
        	}
        }
        
        super.start(configManager, config);
        
        Enumeration<?> enumIDPs = _htIDPs.elements();
        while (enumIDPs.hasMoreElements())
        {
            SAML2IDP saml2IDP = (SAML2IDP)enumIDPs.nextElement();
            _mapIDPsOnSourceID.put(new SourceID(saml2IDP.getSourceID()), saml2IDP);
        }
        
        _oLogger.info("Started storage with id: " + _sId);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getID()
     */
    public String getID()
    {
        return _sId;
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.Object, java.lang.String)
     */
    public IIDP getIDP(Object id, String type) throws OAException
    {
        if (type.equals(SAML2IDP.TYPE_ID) && id instanceof String)
            return getIDP((String)id);
        else if (type.equals(SAML2IDP.TYPE_SOURCEID) && id instanceof byte[])
            return getIDPBySourceID((byte[])id);

        //else not supported
        return null;
    }
    
    /**
     * @see com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage#stop()
     */
    public void stop()
    {
        if (_mapIDPsOnSourceID != null)
            _mapIDPsOnSourceID.clear();
        
        // Clean up the MetadataProviderManager?
        if (_bOwnMPM) {
        	_oLogger.info("Cleaning up MetadataProviderManager '"+_sMPMId+"'");
        	MdMgrManager.getInstance().deleteMetadataProviderManager(_sMPMId);
        }
        
        super.stop();
    }

    /**
     * @see com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage#createIDP(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    protected IIDP createIDP(IConfigurationManager configManager, Element config)
        throws OAException
    {
        SAML2IDP saml2IDP = null;
        
        try
        {
            String sID = configManager.getParam(config, "id");
            if (sID == null)
            {
                _oLogger.error(
                    "No 'id' item found in 'organization' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            byte[] baSourceID = generateSHA1(sID);
            
            String sFriendlyName = configManager.getParam(config, "friendlyname");
            if (sFriendlyName == null)
            {
                _oLogger.error("No 'friendlyname' item found in 'organization' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sDateLastModified = configManager.getParam(config, "lastmodified");
            Date dLastModified = null;
            
            if (sDateLastModified != null) {
            	// Convert to java.util.Date
            	try {
	            	DateTime dt = ISODateTimeFormat.dateTimeNoMillis().parseDateTime(sDateLastModified);
            		dLastModified = dt.toDate();
            	} catch (IllegalArgumentException iae) {
            		_oLogger.info("Invalid 'lastmodified' timestamp provided: "+sDateLastModified+"; ignoring.");
            		dLastModified = null;
            	}
            }
            
            String sMetadataURL = null;
            int iMetadataURLTimeout = -1;
            String sMetadataFile = null;
            
            Element eMetadata = configManager.getSection(config, "metadata");
            if (eMetadata == null)
            {
                _oLogger.warn(
                    "No optional 'metadata' section found in configuration for organization with id: " 
                    + sID);
            }
            else
            {
                Element eHttp = configManager.getSection(eMetadata, "http");
                if (eHttp == null)
                {
                    _oLogger.warn(
                        "No optional 'http' section in 'metadata' section found in configuration for organization with id: " 
                        + sID);
                }
                else
                {
                    sMetadataURL = configManager.getParam(eHttp, "url");
                    if (sMetadataURL == null)
                    {
                        _oLogger.error(
                            "No 'url' item in 'http' section found in configuration for organization with id: " 
                            + sID);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                                
                    URL urlTarget = null;
                    try
                    {
                        urlTarget = new URL(sMetadataURL);
                    }
                    catch (MalformedURLException e)
                    {
                        _oLogger.error(
                            "Invalid 'url' item in 'http' section found in configuration: " 
                            + sMetadataURL, e);
                        throw new OAException(SystemErrors.ERROR_INIT);
                    }
                    
                    StringBuffer sbInfo = new StringBuffer("Organization '");
                    sbInfo.append(sID);
                    sbInfo.append("' uses metadata from url: ");
                    sbInfo.append(sMetadataURL);
                    _oLogger.info(sbInfo.toString());
                    
                    try
                    {
                        URLConnection urlConnection = urlTarget.openConnection();
                        urlConnection.setConnectTimeout(3000);
                        urlConnection.setReadTimeout(3000);
                        urlConnection.connect();
                    }
                    catch (IOException e)
                    {
                        _oLogger.warn(
                            "Could not connect to 'url' item in 'http' section found in configuration: " 
                            + sMetadataURL, e);
                    }
                    
                    String sTimeout = configManager.getParam(eHttp, "timeout");
                    if (sTimeout != null)
                    {
                        try
                        {
                            iMetadataURLTimeout = Integer.parseInt(sTimeout);
                        }
                        catch (NumberFormatException e)
                        {
                            _oLogger.error(
                                "Invalid 'timeout' item in 'http' section found in configuration (must be a number): " 
                                + sTimeout, e);
                            throw new OAException(SystemErrors.ERROR_INIT);
                        }
                        
                        if (iMetadataURLTimeout < 0)
                        {
                            _oLogger.error(
                                "Invalid 'timeout' item in 'http' section found in configuration: " 
                                + sTimeout);
                            throw new OAException(SystemErrors.ERROR_INIT);
                        }
                    }
                }
                
                sMetadataFile = configManager.getParam(eMetadata, "file");
                if (sMetadataFile == null)
                {
                    _oLogger.warn(
                        "No optional 'file' item in 'metadata' section found in configuration for organization with id: " 
                        + sID);
                }
                else
                {
                	// Translate the path
                	sMetadataFile = PathTranslator.getInstance().map(sMetadataFile);
                	
                    File fMetadata = new File(sMetadataFile);
                    if (!fMetadata.exists())
                    {
                        _oLogger.error("Configured metadata 'file' doesn't exist: " 
                            + sMetadataFile);
                        throw new OAException(SystemErrors.ERROR_INIT);
                    }
                    
                    StringBuffer sbInfo = new StringBuffer("Organization '");
                    sbInfo.append(sID);
                    sbInfo.append("' uses metadata in file: ");
                    sbInfo.append(sMetadataFile);
                    _oLogger.info(sbInfo.toString());
                }
            }
            
            Boolean boolACSIndex = new Boolean(true);
            String sACSIndex = configManager.getParam(config, "acs_index");
            if (sACSIndex != null)
            {
                if (sACSIndex.equalsIgnoreCase("FALSE"))
                    boolACSIndex = new Boolean(false);
                else if (!sACSIndex.equalsIgnoreCase("TRUE"))
                {
                    _oLogger.error("Invalid 'acs_index' item value found in configuration: " 
                        + sACSIndex);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            Boolean boolScoping = new Boolean(true);
            String sScoping = configManager.getParam(config, "scoping");
            if (sScoping != null)
            {
                if (sScoping.equalsIgnoreCase("FALSE"))
                    boolScoping = new Boolean(false);
                else if (!sScoping.equalsIgnoreCase("TRUE"))
                {
                    _oLogger.error("Invalid 'scoping' item value found in configuration: " 
                        + sScoping);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            Boolean boolNameIDPolicy = new Boolean(true);
            String sNameIDFormat = null;
            Boolean boolAllowCreate = null;
            
            Element eNameIDPolicy = configManager.getSection(config, "nameidpolicy");
            if (eNameIDPolicy != null)
            {
                String sNameIDPolicyEnabled = configManager.getParam(eNameIDPolicy, "enabled");
                if (sNameIDPolicyEnabled != null)
                {
                    if (sNameIDPolicyEnabled.equalsIgnoreCase("FALSE"))
                        boolNameIDPolicy = new Boolean(false);
                    else if (!sNameIDPolicyEnabled.equalsIgnoreCase("TRUE"))
                    {
                        _oLogger.error("Invalid 'enabled' item value in 'nameidpolicy' section found in configuration: " 
                            + sNameIDPolicyEnabled);
                        throw new OAException(SystemErrors.ERROR_INIT);
                    }
                }
                
                if (boolNameIDPolicy)
                {
                    String sAllowCreate = configManager.getParam(eNameIDPolicy, "allow_create");
                    if (sAllowCreate != null)
                    {
                        if (sAllowCreate.equalsIgnoreCase("TRUE"))
                            boolAllowCreate = new Boolean(true);
                        else if (sAllowCreate.equalsIgnoreCase("FALSE"))
                            boolAllowCreate = new Boolean(false);
                        else
                        {
                            _oLogger.error("Invalid 'allow_create' item value found in configuration: " 
                                + sAllowCreate);
                            throw new OAException(SystemErrors.ERROR_INIT);
                        }
                    }
                    
                    sNameIDFormat = configManager.getParam(eNameIDPolicy, "nameidformat");
                }
            }
            
            Boolean boolAvoidSubjectConfirmation = new Boolean(false);	// default: don't avoid
            String sAvoidSC= configManager.getParam(config, "avoid_subjectconfirmation");
            if (sAvoidSC != null)
            {
                if (sAvoidSC.equalsIgnoreCase("TRUE"))
                	boolAvoidSubjectConfirmation = new Boolean(true);
                else if (!sAvoidSC.equalsIgnoreCase("FALSE"))
                {
                    _oLogger.error("Invalid 'avoid_subjectconfirmation' item value found in configuration: " 
                        + sAvoidSC);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            
            saml2IDP = new SAML2IDP(sID, baSourceID, sFriendlyName, 
                sMetadataFile, sMetadataURL, iMetadataURLTimeout, boolACSIndex, 
                boolAllowCreate, boolScoping, boolNameIDPolicy, sNameIDFormat, 
                boolAvoidSubjectConfirmation, dLastModified, _sMPMId);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _oLogger.fatal("Internal error while reading organization configuration", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return saml2IDP;
    }

    /**
     * Resolves the organization specified by it's SourceID.
     *
     * @param baSourceID The SourceID of the organization
     * @return Organization The requested organization object
     */
    protected SAML2IDP getIDPBySourceID(byte[] baSourceID)
    {
        return _mapIDPsOnSourceID.get(new SourceID(baSourceID));
    }

    private byte[] generateSHA1(String id) throws OAException
    {
        try
        {
            MessageDigest dig = MessageDigest.getInstance("SHA-1");
            return dig.digest(id.getBytes("UTF-8"));
        }
        catch (NoSuchAlgorithmException e)
        {
            _oLogger.error("SHA-1 not supported", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (UnsupportedEncodingException e)
        {
            _oLogger.error("UTF-8 not supported", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
