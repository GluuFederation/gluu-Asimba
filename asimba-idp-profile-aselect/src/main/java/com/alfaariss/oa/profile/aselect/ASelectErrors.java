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
package com.alfaariss.oa.profile.aselect;

/**
 * Error codes according to the A-Select protocol.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface ASelectErrors
{
    /** 0000 */
    public final static String ERROR_ASELECT_SUCCESS = "0000";
    /** 0001 */
    public final static String ERROR_ASELECT_INTERNAL_ERROR = "0001";
    /** 0002 */
    public final static String ERROR_ASELECT_UDB_UNKNOWN_USER = "0002";
    /** 0003 */
    public final static String ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER = "0003";
    /** 0005 */
    public final static String ERROR_ASELECT_SERVER_TGT_EXPIRED = "0005";
    /** 0007 */
    public final static String ERROR_ASELECT_SERVER_UNKNOWN_TGT = "0007";
    /** 0008 */
    public final static String ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED = "0008";
    /** 0030 */
    public final static String ERROR_ASELECT_SERVER_INVALID_REQUEST = "0030";
    /** 0031 */
    public final static String ERROR_ASELECT_SERVER_UNKNOWN_APP = "0031";
    /** 0032 */
    public final static String ERROR_ASELECT_SERVER_INVALID_APP_URL = "0032";
    /** 0033 */
    public final static String ERROR_ASELECT_SERVER_ID_MISMATCH = "0033";
    /** 0035 */
    public static final String ERROR_ASELECT_SERVER_INVALID_APP_LEVEL = "0035";
    /** 0040 */
    public final static String ERROR_ASELECT_SERVER_CANCEL = "0040";
    /** 0102 */
    public final static String ERROR_ASELECT_SERVER_SESSION_EXPIRED = "0102";
    /** 4007 */
    public final static String ERROR_ASELECT_USE_ERROR = "4007";
    /** 4010 */
    public final static String ERROR_ASELECT_UNKNOWN_USER = "4010";
    /** 9001 */
    public final static String ERROR_USER_BLOCKED = "9001";
    /** 9901 */
    public final static String ERROR_MISSING_REQUIRED_ATTRIBUTE = "9901";
    /** 9911 */
    public final static String ERROR_LOGOUT_FAILED = "9911";
    /** 9912 */
    public final static String ERROR_LOGOUT_PARTIALLY = "9912";
    /** 9921 */
    public final static String ERROR_PASSIVE_FAILED = "9921";
}
