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
package com.alfaariss.oa.authentication.password.radius;

import java.net.InetAddress;
import java.net.UnknownHostException;

import net.jradius.client.RadiusClient;
import net.jradius.client.auth.RadiusAuthenticator;
import net.jradius.dictionary.Attr_UserName;
import net.jradius.dictionary.Attr_UserPassword;
import net.jradius.exception.RadiusException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusPacket;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractResourceHandler;

/**
 * A Radius protocol resource. For every Radius resource configured in the
 * Password Authentication Handler section a RadiusProtocolResource will be initialized.
 */
public class RadiusProtocolResource extends AbstractResourceHandler
{
    private final Log _logger;
    private InetAddress _inetAddress = null;
    private String _sSharedSecret = null;
    private RadiusAuthenticator _radiusAuthenticator = null;
    private int _iServerRetries = 0;
    private RadiusClient _radiusClient = null;

    /**
     * Default constructor of <code>RadiusProtocolResource</code>.
     */
    public RadiusProtocolResource()
    {
        super();
        _logger = LogFactory.getLog(RadiusProtocolResource.class);
    }

    /**
     * Processes the configuration for this resource.
     * @param configurationManager The <code>ConfigurationManager</code>.
     * @param eConfig The configuration.
     * @param iServerRetries The number of server retries.
     * @throws OAException if initialization fails.
     */
    public void init(IConfigurationManager configurationManager,
        Element eConfig, int iServerRetries) throws OAException
    {
        super.init(configurationManager,eConfig);

        _iServerRetries = iServerRetries;

        try
        {
            if(eConfig == null)
            {
                _logger.error(
                    "No 'resource' section found in 'password_resource' section in Radius authentication handler configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            //get authentication method.
            String sMethod = _configurationManager.getParam(eConfig, "method");
            if((sMethod == null) || sMethod.trim().equals(""))
            {
                _logger.error(
                    "No 'method' parameter found in 'resource' section in Radius authentication method configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            Class cAuthenticationMethod = null;
            try
            {
                cAuthenticationMethod = Class.forName(sMethod);
            }
            catch (Exception e)
            {
                _logger.error(" class not found: " + sMethod);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            try
            {
                _radiusAuthenticator = (RadiusAuthenticator)cAuthenticationMethod.newInstance();
            }
            catch(Exception e)
            {
                _logger.error("Class could not be instantiated: " + sMethod);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }


            //get RADIUS server host or using default localhost.
            String sHost = _configurationManager.getParam(eConfig, "host");
            if((sHost == null) || sHost.trim().equals(""))
            {
                _logger.info("No 'host' parameter found in RADIUS 'resource' section, using default host: 'localhost'");
                sHost = "localhost";
            }
            try
            {
                _inetAddress = InetAddress.getByName(sHost);
            }
            catch(UnknownHostException e)
            {
                _logger.error("Unable to resolve host: " + sHost);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            //get RADIUS auth_port or using default 1812.
            int iAuthPort = 0;
            String sAuthPort = _configurationManager.getParam(eConfig, "auth_port");
            if((sAuthPort == null) || sAuthPort.trim().equals(""))
            {
                _logger.info("No 'auth_port' found in RADIUS 'resource' section, using default auth_port: '1812'");
                sAuthPort = "1812";
            }
            try
            {
                iAuthPort = Integer.parseInt(sAuthPort);
            }
            catch(NumberFormatException e)
            {
                _logger.error("Invalid format for parameter 'auth_port': " + sAuthPort);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            //get RADIUS acc_port or using default 1812. (for authenticating purposes accounting is not necessary)
            int iAccPort = 0;
            String sAccPort = _configurationManager.getParam(eConfig, "acc_port");
            if((sAccPort == null) || sAccPort.trim().equals(""))
            {
                _logger.info("No 'acc_port' found in RADIUS 'resource' section, using default acc_port: '1813'");
                sAccPort = "1813";
            }

            try
            {
                iAccPort = Integer.parseInt(sAccPort);
            }
            catch(NumberFormatException e)
            {
                _logger.error("Invalid format for parameter 'acc_port': " + sAccPort);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            //get RADIUS server timeout or using default of 60 seconds.
            int iTimeout = 0;
            String sTimeout = _configurationManager.getParam(eConfig, "timeout");
            if((sTimeout == null) || sTimeout.trim().equals(""))
            {
                _logger.info("No 'timeout' found in RADIUS 'resource' section, using default timeout: '60' seconds");
                sTimeout = "60";
            }

            try
            {
                iTimeout = Integer.parseInt(sTimeout);
            }
            catch(NumberFormatException e)
            {
                _logger.error("Invalid format for parameter 'timeout': " + sTimeout);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            //get RADIUS shared_secret.
            _sSharedSecret = _configurationManager.getParam(eConfig, "shared_secret");
            if((_sSharedSecret == null) || _sSharedSecret.trim().equals(""))
            {
                _logger.error("No 'shared_secret' found in RADIUS 'resource' section.");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            AttributeFactory.loadAttributeDictionary(
            "net.jradius.dictionary.AttributeDictionaryImpl");
            _radiusClient = new RadiusClient(
                _inetAddress,   // InetAddress - Address of remote RADIUS Server
                _sSharedSecret, iAuthPort, iAccPort,  iTimeout);
        }
        catch(OAException e)
        {
            _logger.debug("Error initializing Radius protocol resource", e);
            throw e;
        }
        catch(Throwable e)
        {
            _logger.error("Error initializing Radius protocol resource", e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
    }

    /**
     * Authenticate against the configured resource.
     * @param username the supplied user name.
     * @param password  the supplied password.
     * @return true if authentication is successful and false otherwise.
     * @throws OAException if a user authentication error occurs.
     */
    public boolean authenticate(String password, String username)
        throws OAException
    {
    
        boolean isAuthenticated = false;
        String sUserID = constructUsername(username);
        try
        {
            AttributeList attributeList = new AttributeList();
            attributeList.add(new Attr_UserName(sUserID));
    
    
            AccessRequest request = new AccessRequest(_radiusClient, attributeList);
            request.addAttribute(new Attr_UserPassword(password));
    
            RadiusPacket reply = null;
            try
            {
                reply = _radiusClient.authenticate(request, _radiusAuthenticator, _iServerRetries);
            }
            catch(RadiusException e)
            {
                _logger.error("Error occured during receiving reply", e);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
    
            if (reply == null)
            {
                _logger.error("Request timed-out");
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE); // Request Timed-out
            }
            isAuthenticated = (reply instanceof AccessAccept);
    
        }
        catch(OAException e)
        {
            //already handled.
            throw e;
        }
        catch(Exception e)
        {
            _logger.error("Unexpected runtime error occured",e);
            throw new OAException(SystemErrors.ERROR_INTERNAL); // Request Timed-out
        }
        return isAuthenticated;
    }
}
