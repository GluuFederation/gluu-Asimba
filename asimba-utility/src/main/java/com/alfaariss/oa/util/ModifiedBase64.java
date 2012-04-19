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
package com.alfaariss.oa.util;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;

/**
 * Modified Base64 for URL variant.
 * <br>
 * A modified Base64 for URL variant, where no padding '=' will be used, and 
 * the '+' and '/' characters of standard Base64 are respectively replaced by 
 * '-' and '_', so using URL encoders/decoders is no longer necessary and 
 * has no impact on the length of the encoded value, leaving the same encoded 
 * form intact for use in relational databases, web forms, and object 
 * identifiers in general.
 * 
 * @author MHO
 * @author Alfa & Ariss
 */
public class ModifiedBase64
{
    /** UTF-8 */
    public final static String CHARSET = "UTF-8";
    
    /**
     * Encodes the supplied byte array.
     *
     * @param data byte array containing raw bytes
     * @param charset Charset used for encoding the byte array to a <tt>String</tt>
     * @return String Modified Base64 String representation
     * @throws UnsupportedEncodingException if supplied charset isn't supported
     */
    public static String encode(byte[] data, String charset) 
        throws UnsupportedEncodingException
    {
        byte[] baBase64 = Base64.encodeBase64(data);
        
        String sEncoded = new String(baBase64, charset);
        while(sEncoded.endsWith("="))
        {
            sEncoded = sEncoded.substring(0, sEncoded.length() - 1);
        }
        
        sEncoded = sEncoded.replaceAll("\\+", "-");
        sEncoded = sEncoded.replaceAll("/", "_");

        return sEncoded;
    }
    
    /**
     * Encodes the supplied byte array.
     *
     * @param data byte array containing raw bytes
     * @return String Modified Base64 String representation
     * @throws UnsupportedEncodingException if supplied charset isn't supported
     */
    public static String encode(byte[] data)
        throws UnsupportedEncodingException
    {
        return encode(data, CHARSET);
    }
    
    /**
     * Decodes the supplied data String.
     *
     * @param data string containing the data
     * @param charset Charset used for encoding the byte array to a <tt>String</tt>
     * @return String decoded byte array representation
     * @throws UnsupportedEncodingException if supplied charset isn't supported
     */
    public static byte[] decode(String data, String charset) 
        throws UnsupportedEncodingException
    {
        String sEncoded = data.replaceAll("-", "+");
        sEncoded = sEncoded.replaceAll("_", "/");
        
        while(sEncoded.length() % 4 != 0)
        {
            sEncoded = sEncoded + "=";
        }
        
        byte[] baDecoded = Base64.decodeBase64(sEncoded.getBytes(charset));
        
        return baDecoded;
    }
    
    /**
     * Decodes the supplied data String.
     *
     * @param data string containing the data
     * @return String decoded byte array representation
     * @throws UnsupportedEncodingException if supplied charset isn't supported
     */
    public static byte[] decode(String data) 
        throws UnsupportedEncodingException
    {
        return decode(data, CHARSET);
    }
}
