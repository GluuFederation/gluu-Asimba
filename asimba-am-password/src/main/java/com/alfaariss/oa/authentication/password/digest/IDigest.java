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

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Interface for a digest.
 * 
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public interface IDigest
{

    /**
     * Specifies the built-in crypto routines.
     */
    public static final String[] BUILTIN_CRYPTO = {"MD5","SHA1"};

    /**
     * Make a digest according to a specific implementation.
     *
     * @param password The password to use.
     * @param realm The realm to use.
     * @param username The username to use.
     * @return A byte array containing the digest.
     * @throws OAException
     */
    public byte[] digest(
        String password, String realm, String username) throws OAException;
    
    /**
     * Initialize the digester.
     *
     * @param configurationManager The configuration manager.
     * @param eDigest The configuration section.
     * @throws OAException If configuration can not be read or 
     *  specific problems with digester.
     * @since 1.0
     */
    public void init(
        IConfigurationManager configurationManager, 
        Element eDigest) throws OAException;

}
