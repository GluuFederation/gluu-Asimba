/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2013 Asimba
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
package org.asimba.utility.attributes;

import java.net.URLDecoder;
import java.util.Vector;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;

/**
 * Helper functionality to work with attributes
 * 
 * @author mdobrinic
 *
 */
public class AttributeHelper {

	/** Local logger instance */
	private static Log _oLogger = LogFactory.getLog(AttributeHelper.class);
	
	
    /**
     * Deserializes remote attributes.
     * 
     * @param sSerializedAttributes the serialized attributes string.
     * @param sCharSet Character set of the serialized string
     * @param oAttributes the attributes object to which the attributes will be added.
     * @return UserAttributes object containing the serialized attributes.
     * @throws OAException if deserialization fails.
     */
    //Suppresswarnings is unchecked because the (Vector<String>) cast will generate a warning.
    @SuppressWarnings("unchecked")
    public static IAttributes deserializeAttributes(String sSerializedAttributes, String sCharSet, 
        IAttributes oAttributes) throws OAException
    {
        try
        {
            //base64 decode
            byte[] baUserAttrs = Base64.decodeBase64(sSerializedAttributes.getBytes(sCharSet));
            String sDecodedUserAttrs = new String(baUserAttrs, sCharSet);
            
            //decode & and = chars
            String[] saAttrs = sDecodedUserAttrs.split("&");
            for (int i = 0; i < saAttrs.length; i++)
            {
                int iEqualChar = saAttrs[i].indexOf("=");
                String sKey = "";
                String sValue = "";
                Vector<String> vVector = null;
                
                if (iEqualChar > 0)
                {
                    sKey = URLDecoder.decode(
                        saAttrs[i].substring(0 , iEqualChar), sCharSet);
                    
                    sValue = URLDecoder.decode(
                        saAttrs[i].substring(iEqualChar + 1), sCharSet);
                    
                    if (sKey.endsWith("[]"))
                    {  //its a multi-valued attribute
                        // Strip [] from sKey
                        sKey = sKey.substring(0, sKey.length() - 2);
                        
                        if ((vVector = (Vector<String>)oAttributes.get(sKey)) == null)
                            vVector = new Vector<String>();                                
                        
                        vVector.add(sValue);
                    }                        
                }
                else
                    sKey = URLDecoder.decode(saAttrs[i], sCharSet);
                
                if (vVector != null)
                    //store multivalue attribute
                    oAttributes.put(sKey, vVector);
                else
                    //store singlevalue attribute
                    oAttributes.put(sKey, sValue);
            }
        }
        catch (Exception e)
        {
            _oLogger.fatal("Internal error during deserialization of attributes", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return oAttributes;
    }

}
