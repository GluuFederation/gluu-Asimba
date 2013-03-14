/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.aselect.idp.storage.config;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.remote.aselect.idp.storage.ASelectIDP;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage;

/**
 * Uses the configuration as IDP storage.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class IDPConfigStorage extends AbstractConfigurationStorage
{
    private final static String DEFAULT_ID = "aselect";
    
    private String _sID;
    
    /**
     * @see com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configManager, Element config)
        throws OAException
    {
        _sID = configManager.getParam(config, "id");
        if (_sID == null)
        {
            _logger.info("No optional 'id' item for storage configured, using default");
            _sID = DEFAULT_ID;
        }
        
        super.start(configManager, config);
        
        _logger.info("Started storage with id: " + _sID);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getID()
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.Object, java.lang.String)
     */
    public IIDP getIDP(Object id, String type)
    {
        if (type.equals("id") && id instanceof String)
            return getIDP((String)id);
        
        //else not supported
        return null;
    }

    /**
     * @see com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage#createIDP(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    protected IIDP createIDP(IConfigurationManager configManager, Element config)
        throws OAException
    {
        ASelectIDP oASelectIDP = null;
        try
        {
            String sServerID = configManager.getParam(config, "server_id");
            if (sServerID == null)
            {
                _logger.error("No 'server_id' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sOrganizationID = configManager.getParam(config, "id");
            if (sOrganizationID == null)
            {
                _logger.error("No 'id' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sFriendlyname = configManager.getParam(config, "friendlyname");
            if (sFriendlyname == null)
            {
                _logger.error("No 'friendlyname' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sURL = configManager.getParam(config, "url");
            if (sURL == null)
            {
                _logger.error("No 'url' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            URL urlTarget = null;
            try
            {
                urlTarget = new URL(sURL);
            }
            catch (MalformedURLException e)
            {
                _logger.error("Invalid 'url' parameter found in configuration: " + sURL);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                URLConnection urlConnection = urlTarget.openConnection();
                urlConnection.setConnectTimeout(3000);
                urlConnection.setReadTimeout(3000);
                urlConnection.connect();
            }
            catch (IOException e)
            {
                _logger.warn("Could not connect to 'url' parameter found in configuration: " + sURL);
            }
            
            String sLevel = configManager.getParam(config, "level");
            if (sLevel == null)
            {
                _logger.error("No 'level' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            int iLevel;
            try
            {
                iLevel = Integer.parseInt(sLevel);
            }
            catch(NumberFormatException e)
            {
                _logger.error("Invalid 'level' parameter found in configuration, not a number: " + sLevel);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            String sCountry = configManager.getParam(config, "country");
            if (sCountry == null)
                _logger.info("No optional 'country' parameter found in configuration");
            
            String sLanguage = configManager.getParam(config, "language");
            if (sLanguage == null)
                _logger.info("No optional 'language' parameter found in configuration");
                
            boolean bDoSigning = false;
            String sSigning = configManager.getParam(config, "signing");
            if (sSigning != null)
            {
                if (sSigning.equalsIgnoreCase("TRUE"))
                    bDoSigning = true;
                else if (!sSigning.equalsIgnoreCase("FALSE"))
                {
                    _logger.error("Invalid 'signing' parameter found in configuration, must be 'true' or 'false': " + sSigning);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            boolean bASynchronousLogout = false;
            String sASynchronousLogout = configManager.getParam(config, "asynchronouslogout");
            if (sASynchronousLogout != null)
            {
                if (sASynchronousLogout.equalsIgnoreCase("TRUE"))
                    bASynchronousLogout = true;
                else if (!sASynchronousLogout.equalsIgnoreCase("FALSE"))
                {
                    _logger.error("Invalid 'asynchronouslogout' parameter found in configuration, must be 'true' or 'false': " + sASynchronousLogout);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            boolean bSynchronousLogout = false;
            String sSynchronousLogout = configManager.getParam(config, "synchronouslogout");
            if (sSynchronousLogout != null)
            {
                if (sSynchronousLogout.equalsIgnoreCase("TRUE"))
                    bSynchronousLogout = true;
                else if (!sSynchronousLogout.equalsIgnoreCase("FALSE"))
                {
                    _logger.error("Invalid 'synchronouslogout' parameter found in configuration, must be 'true' or 'false': " + sSynchronousLogout);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            boolean bSendArpTarget = false;
            String sSendArpTarget = configManager.getParam(config, "send_arp_target");
            if (sSendArpTarget != null)
            {
                if (sSendArpTarget.equalsIgnoreCase("TRUE"))
                    bSendArpTarget = true;
                else if (!sSendArpTarget.equalsIgnoreCase("FALSE"))
                {
                    _logger.error("Invalid 'send_arp_target' parameter found in configuration, must be 'true' or 'false': " + sSigning);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            oASelectIDP = new ASelectIDP(sOrganizationID, 
                sFriendlyname, sServerID, sURL, iLevel, bDoSigning, sCountry, 
                sLanguage, bASynchronousLogout, bSynchronousLogout, bSendArpTarget);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during create", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        } 
        return oASelectIDP;
    }

}
