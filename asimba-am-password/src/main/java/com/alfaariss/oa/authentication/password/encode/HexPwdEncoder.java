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
package com.alfaariss.oa.authentication.password.encode;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Hex;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.IPasswordHandler;



/**
 * Encoder to hex (byte-array to string representation)
 * 
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public class HexPwdEncoder implements IEncoder
{
    /**
     * @see IEncoder#init(IConfigurationManager, org.w3c.dom.Element)
     */
    public void init(IConfigurationManager configurationManager, Element encoder)
        throws OAException
    {
       //nothing        
    }

    /**
     * @see IEncoder#getBytes(java.lang.String)
     */
    public byte[] getBytes(String input)
    {
        try
        {
            return getBytes(input.getBytes(IPasswordHandler.CHARSET));
        }
        catch (UnsupportedEncodingException e)
        {
            return getBytes(input.getBytes());
        }
    }

    /**
     * @see IEncoder#getString(byte[])
     */
    public String getString(byte[] input)
    {
        String result = new String(
            Hex.encodeHex(input) );

        return result;
    }

    /**
     * @see IEncoder#getBytes(byte[])
     */
    public byte[] getBytes(byte[] input)
    {
        try
        {
            return getString(input).getBytes(IPasswordHandler.CHARSET);
        }
        catch (UnsupportedEncodingException e)
        {
            return getString(input).getBytes();
        }

    }
}
