/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.password.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.IPasswordHandler;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;

/**
 * Crypto Digester. Uses the builtin message digest.
 *
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public class CryptoDigest implements IDigest
{
    /**
     * The password method.
     */
    protected final String _sPasswordMethod;

    private final Log _logger;

    /**
     * The provider to use
     */
    protected String _sProvider;
   
    /**
     * Constructor. Uses given digest.
     * @param method The given method.
     */
    public CryptoDigest (String method)
    {
        _sPasswordMethod = method;
        _sProvider = null;
        _logger = LogFactory.getLog(this.getClass());
    }
    
    /**
     * Read provider configuration.
     * @see com.alfaariss.oa.authentication.password.digest.IDigest#init(
     *  IConfigurationManager, org.w3c.dom.Element)
     */
    public void init(IConfigurationManager configurationManager, 
        Element eDigest) throws OAException
    {
        _sProvider = configurationManager.getParam(eDigest, "provider");
        if (_sProvider == null)
        {
            // DD If no provider is configured for password method, the engine provider is used
            try
            {
                CryptoManager crypto = Engine.getInstance().getCryptoManager();
                _sProvider = crypto.getMessageDigest().getProvider().getName();
                _logger.info(
                    "No provider configured, using the engine provider");
            }
            catch (Exception e)
            {
                _logger.error(
                    "Could not retrieve crypto provider from engine", e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }        
    }

    /**
     * @see IDigest#digest(java.lang.String, java.lang.String, java.lang.String)
     */
    public byte[] digest(String password, String realm, String username)
    throws OAException
    {

        try
        {
            MessageDigest oMessageDigest;
            if (_sProvider != null)
            {
                oMessageDigest = MessageDigest.getInstance(_sPasswordMethod,
                    _sProvider);
            }
            else
            {
                oMessageDigest = MessageDigest.getInstance(_sPasswordMethod);

            }
            oMessageDigest.update(password.getBytes(IPasswordHandler.CHARSET));
            return oMessageDigest.digest();
        }
        catch (NoSuchAlgorithmException e)
        {
            _logger.error("No such algorithm found: " + _sPasswordMethod, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        catch (Exception e)
        {
            _logger.fatal("Could not create message digest", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
    }
}