/*
 * Asimba Server
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
package com.alfaariss.oa.util.saml2;

import java.util.Hashtable;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.management.MdMgrManager;
import org.asimba.util.saml2.metadata.provider.management.MetadataProviderManagerUtil;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;

/**
 * SAML2 Requestors, used to manage SAML2Requestor instances.
 * 
 * When configured through ConfigManager, the ISAML2Requestors are loaded only on startup
 and ISAML2Requestors are maintained in a locally cached HashMap.
 When configured through other means (JDBC), each time a Requestor is asked for,
 it is instantiated.
 
  Note that a ISAML2Requestors instance is always tied to a ProfileID, typically the
  SAML2 IDP Profile for which the ISAML2Requestors are managed. This is necessary to
  establish the property-names for a Requestor
  
 Configuration like:
 <requestors signing="[true/false]">
 *   <mp_manager id="[id-value]" primary="[true/false]" />
 *   <requestor ...>
 *   	[requestor-configuration]
 *   </requestor>
 * </requestors>
 
 #signing : optional attribute to indicate whether default-signing should be enabled 
 		for a SAML2Requestor
 
 mp_manager : optional configuration for metadataprovider manager; if the configuration is
 		not provided, a MetadataProviderManager is used by the name of the Profile; if it is
 		created, it will also be removed upon destroy() of the SAMLRequestors
 #id : attribute that indicates the id of the MetadataProviderManager
 		that is responsible for managing the MetadataProvider for a SAML2Requestor; when
 		mpmanaged_id is not set, the profileId is used to identify the MetadataProviderManager
 #primary : if true, and if the manager was instantiated, the manager will also be destroyed
 		when destroy() of the ISAML2Requestors is called. Defaults to false. 
 *  
 * @author mdobrinic
 * @author MHO
 * @author Alfa & Ariss
 */
public class SAML2Requestors implements ISAML2Requestors
{
	/** Configuration elements */
	public static final String EL_MPMANAGER = "mp_manager";
	public static final String EL_REQUESTOR = "requestor";
	
	public static final String ATTR_SIGNING = "signing";
	public static final String ATTR_MPMANAGER_ID = "mpmanager_id";
	
    /** Local logger instance */
    private static final Log _logger = LogFactory.getLog(ISAML2Requestors.class);

    /** Cache of the instantiated ISAML2Requestors, mapping [SAML2Requestor.Id]->[SAML2Requestor-instance] */
    private Map<String, SAML2Requestor> _mapRequestors;
    
    /** Default Signing property when creating a new SAML2Requestor */
    private boolean _bDefaultSigning;
    
    /** The SAML2Profile Id for which this ISAML2Requestors is used */
    private String _sProfileID;
    
    /** The MetadatProviderManager that manages providers for this Requestor pool */ 
    protected String _sMPMId;

    /** Configurable whether the MetadataProvider must be removed upon destroy() */
    protected boolean _bOwnMPM;
    
    /**
     * Constructor.
     * @param configurationManager The config manager.
     * @param config Configuration section; if null, a default initialization is performed.
     * @param sProfileID The OA Profile ID.
     * @throws OAException OAException If creation fails.
     */
    public SAML2Requestors(IConfigurationManager configurationManager, 
        Element config, String sProfileID) throws OAException
    {
        _bDefaultSigning = false;
        _sProfileID = sProfileID;
        _mapRequestors = new Hashtable<String, SAML2Requestor>();
        
        if (config == null) {
        	_logger.info("Using profile@id as MetadataProviderManager Id: '"+_sProfileID+"'");
        	_sMPMId = _sProfileID;
        	
            // Make sure the MetadataProviderManager exists
            if (MetadataProviderManagerUtil.establishMPM(_sMPMId, configurationManager, null)) {
            	_bOwnMPM = true;	// a new MPM was created; take responsibility
            } else {
            	_bOwnMPM = false;	// an existing MPM is used; don't take responsibility
            }

        	return;
        }
        
        try
        {
            String sSigning = configurationManager.getParam(config, ATTR_SIGNING);
            if (sSigning == null) {
                _logger.warn("No default '"+ATTR_SIGNING+"' item in 'requestors' section found in configuration");
            }
            else
            {
                if (sSigning.equalsIgnoreCase("TRUE"))
                    _bDefaultSigning = true;
                else if (!sSigning.equalsIgnoreCase("FALSE")) {
                    _logger.error(
                        "Invalid default '"+ATTR_SIGNING+"' in 'requestors' section found in configuration (must be true or false): "
                        + sSigning);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            _logger.info("Using default signing enabled: " + _bDefaultSigning);
            
            // Establish MetadataProviderManager Id that refers to existing IMetadataProviderManager
            Element elMPManager = configurationManager.getSection(config, EL_MPMANAGER);
            if (elMPManager == null) {
            	_logger.info("Using MetadataProviderManager Id from profile@id: '"+_sProfileID+"'");
            	_sMPMId = _sProfileID;
            } else {
            	_sMPMId = configurationManager.getParam(elMPManager, "id");
            	if (_sMPMId == null) {
            		_logger.error("Missing @id attribute for '"+EL_MPMANAGER+"' configuration");
            		throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            	}
            	_logger.info("Using MetadataProviderManager Id from configuration: '"+_sMPMId+"'");
            }
            
            // Make sure the MetadataProviderManager exists
            boolean bCreated = MetadataProviderManagerUtil.establishMPM(_sMPMId, configurationManager, elMPManager);
            
            if (elMPManager == null) {
            	_bOwnMPM = bCreated;
            } else {
            	String sPrimary = configurationManager.getParam(elMPManager, "primary");
            	if (sPrimary == null ) {
            		_bOwnMPM = bCreated;	// default: own it when it was created by us
            	} else {
            		if ("false".equalsIgnoreCase(sPrimary)) {
            			_bOwnMPM = false;
            		} else if ("true".equalsIgnoreCase(sPrimary)) {
            			_bOwnMPM = true;
            		} else {
            			_logger.error("Invalid value for '@primary': '"+sPrimary+"'");
            			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            		}
            	}
            }
            
            // Initialize the Requestors from configuration
            _mapRequestors = readRequestors(configurationManager, config);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal(
                "Internal error while reading requestors configuration"
                , e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    
    /**
     * Removes the object from memory.
     */
    @Override
    public void destroy()
    {
        if (_mapRequestors != null)
            _mapRequestors.clear();
        
        if (_bOwnMPM) {
        	_logger.info("Cleaning up MetadataProviderManager '"+_sMPMId+"'");
        	MdMgrManager.getInstance().deleteMetadataProviderManager(_sMPMId);
        }
    }
    
    /**
     * Returns the default singing value. 
     * @return TRUE if signing is enabled.
     */
    @Override
    public boolean isDefaultSigningEnabled()
    {
        return _bDefaultSigning;
    }
    
    /**
     * Returns a SAML2 Requestor instance, with SAML2 specific config items.
     * The SAML2Requestor is either instantiated on server startup (through ConfigManager),
 or when no ISAML2Requestors were estblished on startup using ConfigManager, a new
 SAML2Requestor instance is created on the fly (typically when using a JDBC source for 
 Requestor configuration)
     *
     * @param oRequestor The OA requestor object.
     * @return SAML2Requestor or <code>null</code> if supplied IRequestor is <code>null</code>.
     * @throws OAException if requestor object could not be created.
     * @since 1.1
     */
    @Override
    public SAML2Requestor getRequestor(IRequestor oRequestor) throws OAException
    {
        SAML2Requestor oSAML2Requestor = null;
        try
        {
            if (oRequestor == null)
                return null;
            
            oSAML2Requestor = _mapRequestors.get(oRequestor.getID());
            if (oSAML2Requestor == null) {
                oSAML2Requestor = new SAML2Requestor(oRequestor, _bDefaultSigning, _sProfileID, _sMPMId);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal(
                "Internal error resolving a SAML requestor for OA requestor: " 
                + oRequestor.getID(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return oSAML2Requestor;
    }
    
    
    /**
     * Read the &lt;requestor&gt; elements from the configuration, instantiate SAML2Requestor-instances
     * and put them in a map with [requestor.id] -&gt; [SAML2Requestor-instance]
     * 
     * @param oConfigManager ConfigManager for processing configuration
     * @param elConfig requestors-configuration containing &lt;requestor$gt; elements
     * @return Map of instantiated ISAML2Requestors
     * @throws OAException
     */
    protected Map<String, SAML2Requestor> readRequestors(IConfigurationManager 
        oConfigManager, Element elConfig) throws OAException
    {
        Map<String, SAML2Requestor> mapRequestors = new Hashtable<String, SAML2Requestor>();
        try
        {
            IRequestorPoolFactory requestorPoolFactory = 
                Engine.getInstance().getRequestorPoolFactory();
            
            Element eRequestor = oConfigManager.getSection(elConfig, EL_REQUESTOR);
            while (eRequestor != null) {
                SAML2Requestor requestor = new SAML2Requestor(oConfigManager, 
                    eRequestor, _bDefaultSigning, _sMPMId);

                // Integrity checking:
                if (requestorPoolFactory.getRequestor(requestor.getID()) == null) {
                    _logger.error("Configured requestor id is not available in a requestorpool: "+ requestor.getID());
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (mapRequestors.containsKey(requestor.getID())) {
                    _logger.error("Configured requestor id is not unique in configuration: " + requestor.getID());
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                mapRequestors.put(requestor.getID(), requestor);
                
                _logger.info("Added requestor: " + requestor.toString());
                
                eRequestor = oConfigManager.getNextSection(eRequestor);
            }
        } catch (OAException e) {
            throw e;
        } catch(Exception e) {
            _logger.fatal("Internal error while reading requestors configuration", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return mapRequestors;
    }
}
