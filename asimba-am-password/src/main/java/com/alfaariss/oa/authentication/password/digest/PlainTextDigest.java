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

import java.io.UnsupportedEncodingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.IPasswordHandler;

/**
 * Plain text digest. Will perform a ROT-26.
 *
 * @author BNE
 * @author Alfa & Ariss
 */
public class PlainTextDigest implements IDigest
{
    private final Log     _logger;

    /**
     * Constructor.
     */
    public PlainTextDigest() {

        _logger = LogFactory.getLog(this.getClass());
    }
    
    /**
     * @see IDigest#init(IConfigurationManager, org.w3c.dom.Element)
     */
    public void init(IConfigurationManager configurationManager, Element digest)
        throws OAException
    {
        // Nothing        
    }

    /**
     * @see IDigest#digest(java.lang.String, java.lang.String, java.lang.String)
     */
    public byte[] digest(String password, String realm, String username)
    throws OAException
    {
        try
        {
            return password.getBytes(IPasswordHandler.CHARSET);
        }
        catch (UnsupportedEncodingException e)
        {
            _logger.error("UnsupportedEncodingException.", e);

            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

}
