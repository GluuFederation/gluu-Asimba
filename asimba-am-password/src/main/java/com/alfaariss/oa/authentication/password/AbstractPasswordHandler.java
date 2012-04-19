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
package com.alfaariss.oa.authentication.password;

import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * This class contains the shared logic for a password handler.
 */
public abstract class AbstractPasswordHandler implements IPasswordHandler
{
    /**
     * The resource handlers, for which realm usage is enabled.
     */
    protected Hashtable<String, IResourceHandler> _resourceHandlers;
    
    /**
     * The resourcehandler to be used when realm usage is disabled.
     */
    protected IResourceHandler _resourceHandler;

    /**
     * The Default Realm
     */
    protected String _sDefaultRealm;

    private final Log _logger;

    /**
     * Constructor. Must be called by its children.
     */
    public AbstractPasswordHandler ()
    {
        _resourceHandlers = new Hashtable<String, IResourceHandler>();
        _logger = LogFactory.getLog(this.getClass());
    }

    /**
     * Extract the realm for this user.
     * 
     * @param s The string to extract the realm from.
     * @return The realm.
     */
    public String realm(String s)
    {
        int iChar = s.lastIndexOf("@");
        if (iChar > -1)
        {
            return s.substring(iChar, s.length()).toLowerCase();
        }
        
        _logger.debug("No specific realm found for user id: " + s);
        
        if (_sDefaultRealm == null)
            _logger.debug("No default realm configured");

        return _sDefaultRealm;
    }

    /**
     * @see IPasswordHandler#authenticate(java.lang.String, java.lang.String)
     */
    public boolean authenticate(String sFullUserID, String sPassword)
        throws OAException, UserException
    {
        boolean bRet = false;
        IResourceHandler rHandler = null;
        try
        {
            String sRealm = realm(sFullUserID);
            if (sRealm != null)
            {// A proper realm is found.
                if (_resourceHandlers.containsKey(sRealm))
                    rHandler = _resourceHandlers.get(sRealm);
                else if (_resourceHandler == null)
                    _logger.debug("No resource handler found for realm: " + sRealm);
            }

            if (rHandler != null)// Handler found.
                bRet = rHandler.authenticate(sPassword, sFullUserID);
            else if (_resourceHandler != null)
                bRet = _resourceHandler.authenticate(sPassword, sFullUserID);
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal(
                "internal error occured during authentication, could not authenticate",
                e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return bRet;
    }

    /**
     * Load the default values. More specific config must be read in child
     * classes.
     * 
     * @see com.alfaariss.oa.authentication.password.IPasswordHandler#start(com.alfaariss.oa.api.configuration.IConfigurationManager,
     *      org.w3c.dom.Element)
     */
    public void start(IConfigurationManager cm, Element eConfig)
        throws OAException
    {
        try
        {
            // _configurationManager;

            if ((eConfig == null) || (cm == null))
            {
                _logger.error("Config or Element null in handler");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
        }
        catch (OAException e)
        {
            throw e;
        }

    }

    /**
     * @see IPasswordHandler#stop()
     */
    public void stop()
    {
        if (_resourceHandlers != null)
            _resourceHandlers.clear();
        
        _sDefaultRealm = null;
    }

    /**
     * Set the default realm.
     * 
     * @param cm Configuration Manager.
     * @param eConfig The configuration element.
     * @throws OAException
     */
    protected void setDefault(IConfigurationManager cm, Element eConfig)
    throws OAException
    {
        Element eDefaultSection = cm.getSection(eConfig, "default");

        if (eDefaultSection == null)
        {
            _logger.info("No optional default resource realm defined");
        }
        else
        {
            _sDefaultRealm = cm.getParam(eDefaultSection, "realm");
            if ((_sDefaultRealm == null) || _sDefaultRealm.equals(""))
            {
                _logger.error("No default resource realm found");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            // check if realm is valid
            if (!_sDefaultRealm.startsWith("@"))
            {
                _logger
                .error("Invalid default resource realm found. A realm should start with '@'");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sDefaultRealm = _sDefaultRealm.toLowerCase();
            
            // check if default realm is available within the _resourceHandlers
            if (!_resourceHandlers.containsKey(_sDefaultRealm))
            {
                _logger
                .error("No resource realm available for the configured default resource realm: "
                    + _sDefaultRealm);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
    }

    /**
     * Sets the resource handler to be used without realm support.
     * <br>
     * <b>Note:</b> There can only be one resource without a realm.
     * 
     * @param rh The resource handler to be set.
     * @throws OAException If resource handler already available or if there 
     *  are already resource handlers with realms available.
     * @since 1.4
     */
    protected void setResourceHandler(IResourceHandler rh) throws OAException
    {
        if (_resourceHandler != null)
        {
            _logger.error("Cannot set resource handler without realm, resource handler already available");
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        
        _resourceHandler = rh;
    }
    
    /**
     * Add a handler to the resources (hashtable). If one with the same name already exists. An
     * exception is thrown.
     * 
     * @param rh
     *            The resource handler to add.
     * @throws OAException
     */
    protected void addResourceHandler(IResourceHandler rh) throws OAException
    {
        String sResourceRealm = rh.getResourceRealm();
        if (sResourceRealm == null || sResourceRealm.equals(""))
        {
            _logger.error("No realm found");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        // check if realm is valid
        if (!sResourceRealm.startsWith("@"))
        {
            _logger
            .error("No valid realm found. A realm should start with '@'");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        // Check if there is no resource for this resource
        if (_resourceHandlers.containsKey(sResourceRealm.toLowerCase()))
        {
            _logger.error("There is already a resource defined for realm "
                + sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        if(_logger.isDebugEnabled())
        {
            StringBuffer sb = new StringBuffer(
            "Protocolresource for resource with realm '");
            sb.append(sResourceRealm);
            sb.append(
            "' from Password Authentication handler initialized");
            _logger.debug(sb.toString());
        }

        _resourceHandlers.put(sResourceRealm.toLowerCase(), rh);
    }

    /**
     * Instantiate a class based on its name.
     * 
     * @param cName The name of the class to instantiate
     * @return The instantiated class.
     * @throws OAException
     */
    protected IResourceHandler instantiateResourceHandler(String cName) throws OAException
    {
        IResourceHandler result = null;

        try
        {
            result = (IResourceHandler)Class.forName(cName).newInstance();
        }
        catch (InstantiationException e)
        {
            _logger.error("Class instantiate error", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);

        }
        catch (IllegalAccessException e)
        {
            _logger.error("Class instantiate error", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (ClassNotFoundException e)
        {
            _logger.error("Class instantiate error", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }

        return result;
    }
}
