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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.authentication.password.IPasswordHandler;

/**
 * Generate digest for trac.
 * 
 * Format is:
 * <code>
 *  hash :=   MD5(&lt;username&gt;:&lt;realm&gt;:&lt;password&gt;)
 *  resultingline :=    &lt;realm&gt;:&lt;hash&gt;
 * </code>
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public class TracDigest extends CryptoDigest
{
    private final Log _logger;

    /**
     * Constructor. Initialize it with MD5
     */
    public TracDigest() {
        super("MD5");

        _logger = LogFactory.getLog(this.getClass());
    }

    /**
     * @see CryptoDigest#digest(java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public byte[] digest(
        String password, String r, String username) throws OAException
        {
        String realm;
        // Strip the starting "@"
        if (r.startsWith("@")) {
            realm = r.substring(1);
        }
        else
        {
            realm = r;
        }

        _logger.debug("Entering digest for realm: " + r);
        try
        {
            MessageDigest oMessageDigest = MessageDigest.getInstance(_sPasswordMethod);
            //String dString = username + ':' + realm + ':' + password;

            String dString = new StringBuffer(username).
            append(':').
            append(realm).
            append(':').
            append(password).
            toString();


            // Create byte array from "<realm>:"
            byte[] bRealm = (realm + ':').getBytes();

            // Create MD5 over  "<username>:<realm>:<password>"
            oMessageDigest.update(dString.getBytes(IPasswordHandler.CHARSET));

            // Do it
            byte[] dByte2 = oMessageDigest.digest();

            byte[] dByte = new String(Hex.encodeHex(dByte2)).getBytes();

            // Reserve result space.
            byte[] result = new byte[dByte.length + bRealm.length];

            // Prepend "<realm>:"
            System.arraycopy(bRealm, 0, result, 0, bRealm.length);
            System.arraycopy(dByte, 0, result, bRealm.length, dByte.length);

            // Return
            return result;
        }
        catch (NoSuchAlgorithmException e)
        {
            _logger.error("No such algorithm found: " + _sPasswordMethod, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        catch (UnsupportedEncodingException e)
        {
            _logger.error("Unsupported encoding: " + IPasswordHandler.CHARSET,
                e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        catch (Exception e)
        {
            _logger.fatal("Could not create message digest", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        }
}