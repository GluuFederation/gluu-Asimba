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

import java.io.File;
import java.io.Serializable;
import java.util.Date;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;
import org.asimba.util.saml2.metadata.provider.MetadataProviderConfiguration;
import org.asimba.util.saml2.metadata.provider.MetadataProviderUtil;
import org.asimba.util.saml2.metadata.provider.management.MdMgrManager;
import org.asimba.utility.filesystem.PathTranslator;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.Engine;

/**
 * Requestor object containing requestor specific configuration items.
 * 
 * @author MHO
 * @author Alfa & Ariss 
 */
public class SAML2Requestor implements Serializable
{
    private final static long serialVersionUID = 2093412253512956568L;
    
	/** Local logger instance */
	private static Log _logger = LogFactory.getLog(SAML2Requestor.class);

    /** Default request timeout */
    public final static int HTTP_METADATA_REQUEST_TIMEOUT = 5000;
       
    /** ID of the Requestor (represents the SAML2 EntityId) */
    protected String _sID;
    
    /** The configured source(s) for getting SAML2 Metadata from */
    protected MetadataProviderConfiguration _oMetadataProviderConfig;

    /** Signing mandatory. */
    protected boolean _bSigning;
   
    /** Timestamp when the SAML2Requestor was last modified */
    protected Date _dLastModified;
    
    /** The name of the MetadataProviderManager that manages this SAML2Requestor */
    protected String _sMPMId = null;

    /**
     * Keep reference to MetadataProvider for this SAML2Requestor
     * 
     * Does not serialize, so it is lost whenever it has been resuscitated. This should
     * not present any problem, as the MetadataProviderManager can re-deliver the 
     * MetadataProvider, or when it can not, this SAML2Requestor can re-create one
     */
    transient protected MetadataProvider _oMetadataProvider;

    private final static String PROPERTY_SIGNING = ".signing";
    private final static String PROPERTY_METADATA_HTTP_TIMEOUT = ".metadata.http.timeout";
    private final static String PROPERTY_METADATA_HTTP_URL = ".metadata.http.url";
    private final static String METADATA_FILE = ".metadata.file";
    private final static String METADATA = ".metadata";
    
    public final static int DEFAULT_HTTP_CONNECT_TIMEOUT = 3000;
    public final static int DEFAULT_HTTP_READ_TIMEOUT = 3000;
    
    
    /**
     * Constructor.
     * 
     * @param configurationManager The config manager.
     * @param config Configuration section.
     * @param bSigning Default signing boolean.
     * @param sMPMId The name of the MetadataProviderManager that manages the MetadataProvider
     *   for this SAML2Requestor
     * @throws OAException If creation fails.
     */
    public SAML2Requestor(IConfigurationManager configurationManager, 
        Element config, boolean bSigning, String sMPMId) throws OAException
    {
        try
        {
            _sID = configurationManager.getParam(config, "id");
            if (_sID == null) {
                _logger.error("No 'id' item found in 'requestor' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _bSigning = false;
            String sSigning = configurationManager.getParam(config, "signing");
            if (sSigning == null) {
                _logger.warn("No optional 'signing' item found in configuration for requestor with id: " 
                    + _sID);
                _bSigning = bSigning;
            }
            else
            {
                if (sSigning.equalsIgnoreCase("TRUE")) {
                    _bSigning = true;
                }
                else {
                	if (!sSigning.equalsIgnoreCase("FALSE")){
	                    _logger.error("Invalid 'signing' item found in configuration (must be true or false) for requestor with id: "
	                        + _sID);
	                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
	                }
                }
            }
            
            _logger.info("Using signing enabled: " + _bSigning);
            
            String sDateLastModified = configurationManager.getParam(config, "lastmodified");
            _dLastModified = null;
            
            if (sDateLastModified != null) {
            	// Convert to java.util.Date
            	try {
	            	DateTime dt = ISODateTimeFormat.dateTimeNoMillis().parseDateTime(sDateLastModified);
	            	_dLastModified = dt.toDate();
            	} catch (IllegalArgumentException iae) {
            		_logger.warn("Invalid 'lastmodified' timestamp provided: "+sDateLastModified+"; ignoring.");
            		_dLastModified = null;
            	}
            }

            // Keep reference to the MetadataProviderManager
            _sMPMId = sMPMId;
            
            // Do some integrity checking:
            IMetadataProviderManager oMPM = MdMgrManager.getInstance().getMetadataProviderManager(_sMPMId);
            if (oMPM == null) _logger.warn("The MetadataProviderManager '"+_sMPMId+"' does not (yet?) exist!");
            

            // Initialize MetadataProviderConfig
            _oMetadataProviderConfig = getMetadataConfigFromConfig(configurationManager, config);
            
            // Initialize upon construction, as last modification date will not change
            initMetadataProvider();
                        
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error while reading requestors configuration", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    
    /**
     * Constructor which uses business logic requestor properties.
     *  
     * @param oRequestor The OA Requestor object
     * @param bSigning Default signing boolean.
     * @param sProfileId The SAML2 OA Profile id for resolving the attributes.
     * @param sMPMId The name of the MetadataProviderManager that manages the MetadataProvider
     *   for this SAML2Requestor
     * @throws OAException If creation fails.
     * @since 1.1
     */
    public SAML2Requestor(IRequestor oRequestor, boolean bSigning, String sProfileId, String sMPMId) 
        throws OAException
    {
        try
        {
            _sID = oRequestor.getID();

            Map<?, ?> mProperties = oRequestor.getProperties();
        	initFromProperties(mProperties, bSigning, sProfileId);

            // Keep reference to the MetadataProviderManager
            _sMPMId = sMPMId;
            
            // Do some integrity checking:
            IMetadataProviderManager oMPM = MdMgrManager.getInstance().getMetadataProviderManager(_sMPMId);
            if (oMPM == null) _logger.warn("The MetadataProviderManager '"+_sMPMId+"' does not (yet?) exist!");

            // Initialize MetadataProviderC
            _oMetadataProviderConfig = getMetadataConfigFromProperties(mProperties, sProfileId);
            
            // Lazy initialization of actual MetadataProvider
            // initMetadataProvider(oMPC, sProfileId, oRequestor.getLastModified());
        }
        catch (OAException oae) {
    		_logger.error("Exception when initializing MetadataProvider: "+oae.getMessage());
    		throw oae;
        } catch(Exception e) {
            _logger.fatal("Internal error while reading SAML2 attributes for requestor: " 
                + oRequestor.getID(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }


    /**
     * Helper to initialize local instance from provided requestor properties
     * @param oRequestor
     * @param bSigning
     * @param sProfileID
     * @throws OAException
     */
    protected void initFromProperties(Map<?,?> mProperties, boolean bSigning, String sProfileID)
    	throws OAException
    {
        _bSigning = false;
        String sSigning = (String)mProperties.get(sProfileID + PROPERTY_SIGNING);
        if (sSigning == null) {
            _bSigning = bSigning;
            if (_logger.isDebugEnabled()) {
                _logger.debug("No optional '"+sProfileID+PROPERTY_SIGNING+"' property found for requestor '"+
                				_sID+"'; Using default value: "+_bSigning);
            }
        } else {
            if (sSigning.equalsIgnoreCase("TRUE")) {
                _bSigning = true;
            } else if (!sSigning.equalsIgnoreCase("FALSE")) {
                _logger.error("Invalid '"+sProfileID+PROPERTY_SIGNING+"' property found for requestor '"+
                				_sID+"'; Invalid value: "+sSigning);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
    }
    
    
    /**
     * Helper method to initialize the MetadataProvider for the SAML2Requestor
     * Wrapper around MPManager: re-uses cached version, or creates a new version
     * when configuration was changed (since _dLastModified) or when cached version 
     * was expired.<br/>
     * 
     * @throws OAException thrown when unrecoverable error occurred
     */
    protected void initMetadataProvider() throws OAException 
    {
        String sInstanceMPFingerprint = _oMetadataProviderConfig.getFingerprint();
        
        if (sInstanceMPFingerprint.equals(MetadataProviderConfiguration.FINGERPRINT_PROVIDER_UNKNOWN)) {
            _logger.warn("No optional available metadata for requestor with id: "+ _sID);
            return;
        }
        
    	// Establish MetadataProvider for Requestor:
    	IMetadataProviderManager oMPM = null;
    	MetadataProvider oMP = null;

    	oMPM = MdMgrManager.getInstance().getMetadataProviderManager(_sMPMId);
    	
    	if (oMPM == null) _logger.warn("MetadataProviderManager '"+_sMPMId+"'is not available for Requestor '"+_sID+"'; possible thread leak?");
    	
    	// Try to get MetadataProvider from manager
    	if (oMPM != null) oMP = oMPM.getProviderFor(_sID, _dLastModified);
    	
    	// Is the cached MetadataProvider still valid?
    	if (oMP != null) {
    		String sCachedMPFingerprint = MetadataProviderUtil.getMetadataProviderFingerprint(oMP);
    		
    		if (! sCachedMPFingerprint.equals(sInstanceMPFingerprint)) {
    			_logger.info("Metadata configuration changed; re-initializing metadata for "+_sID);
    			// No longer valid; invalidate the version from cache
    			oMPM.removeProviderFor(_sID);
    			oMP = null;
    		} else {
    			// For the purpose of logging:
    			if (_logger.isDebugEnabled()) {
        			String sNextRefresh = null;
        			
        			if (oMP instanceof AbstractReloadingMetadataProvider) {
        				DateTime oNextRefresh = ((AbstractReloadingMetadataProvider) oMP).getNextRefresh();
        				sNextRefresh = oNextRefresh.toString();
        			}
        			_logger.debug("Using cached MetadataProvider for "+_sID+
        					(sNextRefresh==null?"":" (next refresh: "+sNextRefresh+")"));
    			}
    		}
    	}
    	
    	if (oMP == null) {
			oMP = MetadataProviderUtil.createMetadataProvider(_sID, _oMetadataProviderConfig, oMPM);
			
			if (oMP != null) {
				_logger.debug("New MetadataProvider was established for "+_sID);
			} else {
				_logger.debug("No MetadataProvider could be established for "+_sID);
			}
		}
    	
    	_oMetadataProvider = oMP;
    }
    
    
    /**
     * Returns the Requestor ID. 
     * @return String with the Requestor ID.
     */
    public String getID() {
        return _sID;
    }
    
    /**
     * Returns the requestor specific MetadataProvider
     *
     * @return the MetadataProvider or <code>null</code> if no provider was available 
     */
    public MetadataProvider getMetadataProvider() {
    	if (_oMetadataProvider != null) return _oMetadataProvider;
    	
    	try {
    		initMetadataProvider();
    	} catch (OAException oae) {
    		_logger.warn("Exception occurred when establishing MetadataProvider for requestor '"+_sID+"': "+oae.getMessage());
    		return null;
    	}
    	
    	return _oMetadataProvider;
    }
    
    /**
     * Returns TRUE if requests from this Requestor must be signed.
     * 
     * @return TRUE if signing is required for this requestor.
     */
    public boolean isSigningEnabled()
    {
        return _bSigning;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer();
        sbInfo.append("Requestor '");
        sbInfo.append(_sID);
        sbInfo.append("'");
        sbInfo.append(": ");
        sbInfo.append(_oMetadataProviderConfig.getFingerprint());

        return sbInfo.toString();
    }
    
    
    /**
     * Establish Metadata Provider configuration from a configuration element
     * Does not do any validation of the configured settings
     * @param oConfigManager
     * @param elConfig Configuration element of the Requestor (must contain child <metadata> element)
     * @return
     * @throws ConfigurationException 
     */
    protected MetadataProviderConfiguration getMetadataConfigFromConfig(
    		IConfigurationManager oConfigManager, Element elConfig) 
    				throws OAException
    {
    	MetadataProviderConfiguration oMPC = new MetadataProviderConfiguration();

    	Element elMetadata = oConfigManager.getSection(elConfig, "metadata");
    	
    	// Establish full qualified filename
        String sFilename = oConfigManager.getParam(elMetadata, "file");
        if (sFilename != null) sFilename = PathTranslator.getInstance().map(sFilename);
        oMPC._sFilename = sFilename;
        
        // Establish HTTP/URL settings
        Element elHTTP = oConfigManager.getSection(elMetadata, "http");
        if (elHTTP != null) {
        	oMPC._sURL = oConfigManager.getParam(elHTTP, "url");
        	
            String sTimeout = oConfigManager.getParam(elHTTP, "timeout");
            if (sTimeout != null) {
                try {
                    oMPC._iTimeout = Integer.parseInt(sTimeout);
                } catch (NumberFormatException e) {
                    _logger.error("Invalid value for http@timeout-attribute in configuration: " + sTimeout, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
        }
        
        // establish raw XML (untested) from <metadata><raw>...</raw></metadata>
        oMPC._sMetadata = oConfigManager.getParam(elMetadata, "raw");
        
        return oMPC;
    }
    
    
    /**
     * Establish Metadata Provider configuration from requestor properties
     * @param oProperties The set of Requestor Properties
     * @param sProfileId The SAML2 IDP ProfileId to use to look up properties
     * @return
     * @throws OAException 
     */
    protected MetadataProviderConfiguration getMetadataConfigFromProperties(
    		Map<?, ?> mProperties, String sProfileId) throws OAException
    {
    	MetadataProviderConfiguration oMPC = new MetadataProviderConfiguration();

    	// Establish full qualified filename
        String sFilename = (String)mProperties.get(sProfileId + METADATA_FILE);
        if (sFilename != null) sFilename = PathTranslator.getInstance().map(sFilename);
        oMPC._sFilename = sFilename;
        
        // Establish metadata from properties
        oMPC._sMetadata = (String)mProperties.get(sProfileId + METADATA);
        
        // Establish HTTP/URL settings
        oMPC._sURL = (String)mProperties.get(sProfileId + PROPERTY_METADATA_HTTP_URL);
        
        String sTimeout = (String)mProperties.get(sProfileId + PROPERTY_METADATA_HTTP_TIMEOUT);
        if (sTimeout != null) {
        	try {
                oMPC._iTimeout = Integer.parseInt(sTimeout);
            } catch (NumberFormatException e) {
                _logger.error("Invalid value for "+sProfileId + PROPERTY_METADATA_HTTP_TIMEOUT+" property: " + sTimeout, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }

        return oMPC;
    }
    
    
}
