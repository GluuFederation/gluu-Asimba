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

import org.apache.commons.codec.binary.Base64;

import com.alfaariss.oa.OAException;

/**
 * SHA1 Digester for htpasswd.
 * 
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public class HtPasswdSHA1Digest extends CryptoDigest
{
    /**
     * Constructor
     */
    public HtPasswdSHA1Digest() 
    {
        super("SHA1");
    }

    /**
     * @see CryptoDigest#digest(java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[] digest(String password, String realm, String username) throws OAException
    {
        byte[] sha1_bytes = super.digest(password, realm, username);

        Base64 b = new Base64();

        byte[] sha1 = b.encode(sha1_bytes);
        byte[] result = new byte[sha1.length+5];

        System.arraycopy("{SHA}".getBytes(), 0, result, 0, 5);
        System.arraycopy( sha1, 0,result, 5, sha1.length);

        return result;
    }
}