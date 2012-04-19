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
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;

/**
 * Requestors object.
 * @author MHO
 * @author Alfa & Ariss
 */
public class SAML2Requestors
{
    private Map<String, SAML2Requestor> _mapRequestors;
    private Log _logger;
    private boolean _bDefaultSigning;
    private String _sProfileID;

    /**
     * Constructor.
     * @param sProfileID The OA Profile ID.
     * @throws OAException OAException If creation fails.
     */
    public SAML2Requestors(String sProfileID) throws OAException
    {
        _logger = LogFactory.getLog(SAML2Requestors.class);
        try
        {
            _bDefaultSigning = false;
            _sProfileID = sProfileID;
            _logger.info("Using default signing enabled: " + _bDefaultSigning);
            _mapRequestors = new Hashtable<String, SAML2Requestor>();
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
     * Constructor.
     * @param configurationManager The config manager.
     * @param config Configuration section.
     * @param sProfileID The OA Profile ID.
     * @throws OAException OAException If creation fails.
     */
    public SAML2Requestors(IConfigurationManager configurationManager, 
        Element config, String sProfileID) throws OAException
    {
        _logger = LogFactory.getLog(SAML2Requestors.class);
        try
        {
            _bDefaultSigning = false;
            _sProfileID = sProfileID;
                
            String sSigning = configurationManager.getParam(config, "signing");
            if (sSigning == null)
            {
                _logger.warn(
                    "No default 'signing' item in 'requestors' section found in configuration");
            }
            else
            {
                if (sSigning.equalsIgnoreCase("TRUE"))
                    _bDefaultSigning = true;
                else if (!sSigning.equalsIgnoreCase("FALSE"))
                {
                    _logger.error(
                        "Invalid default 'signing' in 'requestors' section found in configuration (must be true or false): "
                        + sSigning);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            _logger.info("Using default signing enabled: " + _bDefaultSigning);
            
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
    public void destroy()
    {
        if (_mapRequestors != null)
            _mapRequestors.clear();
    }
    
    /**
     * Returns the default singing value. 
     * @return TRUE if signing is enabled.
     */
    public boolean isDefaultSigningEnabled()
    {
        return _bDefaultSigning;
    }
    
    /**
     * Returns a SAML2 requestor object with SAML2 specific config items.
     *
     * @param oRequestor The OA requestor object.
     * @return SAML2Requestor or <code>null</code> if supplied IRequestor is <code>null</code>.
     * @throws OAException if requestor object could not be created.
     * @since 1.1
     */
    public SAML2Requestor getRequestor(IRequestor oRequestor) throws OAException
    {
        SAML2Requestor requestor = null;
        try
        {
            if (oRequestor == null)
                return null;
            
            requestor = _mapRequestors.get(oRequestor.getID());
            if (requestor == null)
                requestor = new SAML2Requestor(oRequestor, _bDefaultSigning, 
                    _sProfileID);
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
        return requestor;
    }
    
    private Map<String, SAML2Requestor> readRequestors(IConfigurationManager 
        configurationManager, Element config) throws OAException
    {
        Map<String, SAML2Requestor> mapRequestors = new Hashtable<String, SAML2Requestor>();
        try
        {
            IRequestorPoolFactory requestorPoolFactory = 
                Engine.getInstance().getRequestorPoolFactory();
            
            Element eRequestor = configurationManager.getSection(config, "requestor");
            while (eRequestor != null)
            {
                SAML2Requestor requestor = new SAML2Requestor(configurationManager, 
                    eRequestor, _bDefaultSigning);

                if (requestorPoolFactory.getRequestor(requestor.getID()) == null)
                {
                    _logger.error(
                        "Configured requestor id is not available in a requestorpool: " 
                        + requestor.getID());
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (mapRequestors.containsKey(requestor.getID()))
                {
                    _logger.error(
                        "Configured requestor id is not unique in configuration: " 
                        + requestor.getID());
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                mapRequestors.put(requestor.getID(), requestor);
                
                _logger.info("Added requestor: " + requestor.toString());
                
                eRequestor = configurationManager.getNextSection(eRequestor);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal(
                "Internal error while reading requestors configuration", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return mapRequestors;
    }
}
