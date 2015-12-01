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
 * along with this program. If not, see www.gnu.org/licenses
 * 
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package com.alfaariss.oa.engine.idp.storage.configuration;

import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;

/**
 * IDP Storage implementation using configuration.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @param <IDP> the type of IDP 
 * @since 1.4
 */
abstract public class AbstractConfigurationStorage<IDP extends IIDP> implements IIDPStorage
{
    /** System logger */
    private static Log _logger;
    /** Hashtable containing all IDP's */
    protected Hashtable<String, IDP> _htIDPs;
    /** List containing all IDP's*/
    protected List<IIDP> _listIDPs;

    /**
     * Constructor. 
     */
    public AbstractConfigurationStorage()
    {
        _logger = LogFactory.getLog(this.getClass());
        _htIDPs = new Hashtable<String, IDP>();
        _listIDPs = new Vector<IIDP>();
    }
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#exists(java.lang.String)
     */
    @Override
    public boolean exists(String id)
    {
        return _htIDPs.containsKey(id);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getAll()
     */
    @Override
    public List<IIDP> getAll()
    {
        return Collections.unmodifiableList(_listIDPs);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.String)
     */
    @Override
    public IIDP getIDP(String id)
    {
        return _htIDPs.get(id);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager configManager, Element config)
        throws OAException
    {
        Element eIDP = configManager.getSection(config, "idp");
        while (eIDP != null)
        {
            IDP idp = createIDP(configManager, eIDP);
            
            if (_htIDPs.containsKey(idp.getID()))
            {
                _logger.error("Configured IDP is not unique: " + idp.getID());
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            boolean bEnabled = true;
            String sEnabled = configManager.getParam(config, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Invalid 'signing' parameter found in configuration, must be 'true' or 'false': " + sEnabled);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            if (!bEnabled)
            {
                _logger.info("IDP disabled: " + idp.getID());
            }
            else
            {
                _htIDPs.put(idp.getID(), idp);
                _listIDPs.add(idp);
                
                _logger.info("Found IDP with ID: " + idp.getID());
            }
            
            eIDP = configManager.getNextSection(eIDP);
        }
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#stop()
     */
    @Override
    public void stop()
    {
        if (_listIDPs != null)
            _listIDPs.clear();
        
        if (_htIDPs != null)
            _htIDPs.clear();
    }

    /**
     * Creates the IDP object by reading it's configuration.
     * 
     * @param configManager The configuration manager.
     * @param config The configuration of the IDP object.
     * @return The configured IDP.
     * @throws OAException if IDP could not be created.
     */
    abstract protected IDP createIDP(IConfigurationManager configManager, Element config)
        throws OAException;
}
