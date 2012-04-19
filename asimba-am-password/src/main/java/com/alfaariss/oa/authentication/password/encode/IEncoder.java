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

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Interface for encoders.
 * 
 * //DD Encoder may fallback to default encoding in case of a {@link UnsupportedEncodingException}.
 * 
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public interface IEncoder
{
    /**
     * Encodes the string to bytes.
     * 
     * @param input The input string to convert.
     * @return A byte array.
     */
    public byte[] getBytes(String input);


    /**
     * Encodes a byte array.
     * 
     * @param input A byte array.
     * @return The resulting byte array.
     */
    public byte[] getBytes(byte[] input);


    /**
     * Encode a byte array.
     * @param input The input array
     * @return The resulting string.
     */
    public String getString(byte[] input);
    
    /**
     * Initialize the encoder.
     *
     * @param configurationManager The configuration manager.
     * @param eEncoder The configuration section.
     * @throws OAException If configuration can not be read or 
     *  specific problems with encoder.
     */
    public void init(
        IConfigurationManager configurationManager, 
        Element eEncoder) throws OAException;

}
