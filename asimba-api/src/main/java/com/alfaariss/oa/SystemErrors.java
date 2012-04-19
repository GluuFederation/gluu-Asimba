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
package com.alfaariss.oa;

/**
 * The basic OA system errors.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public final class SystemErrors 
{   
    /** 0000 */
	public static final int OK = 0x0000;
    
    /** 0001 */
	public static final int ERROR_INTERNAL = 0x0001;
    /** 0002 */
    public static final int ERROR_INIT = 0x0002;
    /** 0003 */
    public static final int ERROR_NOT_INITIALIZED = 0x0003;
    /** 0004 */
    public static final int ERROR_RESTART = 0x0004;
    
    /** 0011 */
    public static final int ERROR_CONFIG_READ = 0x0011;
    /** 0012 */
    public static final int ERROR_CONFIG_WRITE = 0x0012;
    /** 0013 */
    public static final int ERROR_CONFIG_DELETE = 0x0013;
    
    /** 0021 */
	public static final int ERROR_RESOURCE_CONNECT = 0x0021;
    /** 0022 */
    public static final int ERROR_RESOURCE_INSERT = 0x0022;
    /** 0023 */
    public static final int ERROR_RESOURCE_RETRIEVE = 0x0023;
    /** 0024 */
    public static final int ERROR_RESOURCE_UPDATE = 0x0024;
    /** 0025 */
    public static final int ERROR_RESOURCE_REMOVE = 0x0025;
    /** 0026 */
	public static final int ERROR_RESOURCE_CLOSE = 0x0026;

    /** 0031 */
    public static final int ERROR_CRYPTO_CREATE = 0x0031;
    /** 0032 */
    public static final int ERROR_CRYPTO_VERIFY = 0x0032;
    /** 0033 */
    public static final int ERROR_CRYPTO_ENCRYPT = 0x0033;
    /** 0034 */
    public static final int ERROR_CRYPTO_DECRYPT = 0x0034;
    
    /** 0041 */
    public static final int ERROR_TGT_MAX = 0x0041;
    /** 0051 */
    public static final int ERROR_SESSION_MAX = 0x0051;
    
    /**
     * Convert error codes for display purposes.
     * @param iCode The error code.
     * @return An 4 digit <code>String</code> representation of the error code. 
     */
    public static String toHexString(int iCode)
    {
        StringBuffer sb = new StringBuffer(4);        
        String sCode = Integer.toHexString(iCode);
        int iFill = 4 - sCode.length();
        for(int i = 0; i < iFill; i++)
            sb.append('0');
        sb.append(sCode);
        return sb.toString();
    }

}