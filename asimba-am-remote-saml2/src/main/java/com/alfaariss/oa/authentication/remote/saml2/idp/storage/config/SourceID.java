/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.idp.storage.config;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * SourceID object to be stored as key in a Map.
 * @author MHO
 * @author Alfa & Ariss
 */
public class SourceID implements Serializable
{
    /** Local logger instance */
    private static Log _oLogger = LogFactory.getLog(IDPConfigStorage.class);
        
    private static final long serialVersionUID = 3773317282651547828L;
    private byte[] _baSourceID;
    
    /**
     * Constructor
     * @param baSourceID
     */
    public SourceID(byte[] baSourceID)
    {
        _baSourceID = baSourceID;
    }
    
    /**
     * Constructor
     * @param baSourceID
     */
    public SourceID(String sID) throws OAException
    {
        _baSourceID = generateSHA1(sID);
    }
    
    /**
     * The {@link java.lang.Object#hashCode()} of the SourceID.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return Arrays.hashCode(_baSourceID);
    }
    
    /**
     * Returns <code>_baSourceID.equals(other._baSourceID)</code>.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof SourceID))
            return false;
        return Arrays.equals(_baSourceID, ((SourceID)other)._baSourceID);
    }
    
    

    private byte[] generateSHA1(String id) throws OAException
    {
        try
        {
            MessageDigest dig = MessageDigest.getInstance("SHA-1");
            return dig.digest(id.getBytes("UTF-8"));
        }
        catch (NoSuchAlgorithmException e)
        {
            _oLogger.error("SHA-1 not supported", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (UnsupportedEncodingException e)
        {
            _oLogger.error("UTF-8 not supported", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
