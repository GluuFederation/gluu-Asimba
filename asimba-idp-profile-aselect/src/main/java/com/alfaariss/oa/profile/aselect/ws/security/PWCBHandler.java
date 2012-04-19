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
package com.alfaariss.oa.profile.aselect.ws.security;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSPasswordCallback;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.crypto.factory.AbstractSigningFactory;


/**
 * Password callback handler for secure webservices.
 *
 * @author EVB
 * @author Alfa & Ariss
 * @since 1.4
 */
public class PWCBHandler implements CallbackHandler 
{
    private static Log _logger = LogFactory.getLog(PWCBHandler.class);
    
    /**
     * Handle the retrieval of the signing key password.
     * 
     * The password and alias are read from the OAS {@link CryptoManager}.
     * @see javax.security.auth.callback.CallbackHandler#handle(
     *  javax.security.auth.callback.Callback[])
     */
    public void handle(Callback[] callbacks) 
        throws IOException, UnsupportedCallbackException 
    {        
        try
        {
            CryptoManager manager = Engine.getInstance().getCryptoManager();
            if(manager == null)
            {
                _logger.warn(
                    "Could not create OACrypto, OAS cryptomanager not initialized");
                throw new OAException(SystemErrors.ERROR_CRYPTO_CREATE);
            }
            
            AbstractSigningFactory asf = manager.getSigningFactory();
            if(asf == null)
            {
                _logger.warn(
                    "Could not create OACrypto, OAS signing not enabled");
                throw new OAException(SystemErrors.ERROR_CRYPTO_CREATE);
            }
            for(Callback callback : callbacks)
            {
                if (callback instanceof WSPasswordCallback) 
                {
                    WSPasswordCallback pc = (WSPasswordCallback)callback;
                    if (pc.getUsage() == WSPasswordCallback.SIGNATURE)
                    {
                        if(asf.getAlias().equals(pc.getIdentifier())) 
                        {
                            String password = asf.getPrivateKeyPassword(); 
                            if(password != null)
                                pc.setPassword(password);
                        }               
                    }
                    else 
                    {
                        _logger.warn("The callback usage is not supported: " + 
                            pc.getUsage());
                        throw new UnsupportedCallbackException(callback, 
                            "Unrecognized Callback usage");
                    }
                } 
                else 
                {
                    _logger.warn("The callback is not supported: " + callback);
                    throw new UnsupportedCallbackException(
                        callback, "Unrecognized Callback");
                }
               
            }
        }
        catch (OAException e)
        {
            _logger.error("OAS not properly initialized",e);
            throw new IOException("OAS not properly initialized");
        }
    }
}
