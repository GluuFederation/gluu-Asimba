
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
 * All requestor events.
 * 
 * @author EVB
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public enum RequestorEvent
{
    /**
     * Internal error.
     * If an internal error occurrs during client (e.g. user) interaction. 
     */
    INTERNAL_ERROR,
    
    /**
     * Session invalid.
     */
    SESSION_INVALID, 
 
    /**
     * Session expired.
     */
    SESSION_EXPIRED,
    
    /**
     * User unknown.
     */
    USER_UNKNOWN,
    
    /**
     * Discovery of user information (endpoint) successful.
     */
    USER_IDENTIFIED,
    
    /**
     * User not enabled.
     */
    USER_DISABLED,
    
    /**
     * Request invalid.
     */
    REQUEST_INVALID,
    
    /** 
     * Authentication request successful.
     */
    AUTHN_INITIATION_SUCCESSFUL, 
 
    /** 
     * Authentication request failed.
     */
    AUTHN_INITIATION_FAILED, 
 
    /** 
     * Authentication Query successful.
     */
    QUERY_SUCCESSFUL,
 
    /** 
     * Authentication Query failed.
     */
    QUERY_FAILED,
    
    /** 
     * Token dereference succesful.
     * <br>
     * verify_credentials request was successful. 
     */
    TOKEN_DEREFERENCE_SUCCESSFUL,
    
    /** 
     * Token dereference failed.
     * <br>
     * Verify credentials failed.
     */
    TOKEN_DEREFERENCE_FAILED, 
    
    /** 
     * Authentication succesful.
     * <br>
     * authenticate request was successful. 
     */
    AUTHN_SUCCESSFUL,
    
    /** 
     * Authentication failed.
     * <br>
     * Authentication failed.
     */
    AUTHN_FAILED,
    
    /**
     * User logout failed
     * @since 1.4
     */
    LOGOUT_FAILED,
    /**
     * User was only partially loggedout
     * @since 1.4
     */
    LOGOUT_PARTIALLY,
    /**
     * User successfully logged out
     * @since 1.4
     */
    LOGOUT_SUCCESS,
    /** 
     * Logout initiation successful.
     * @since 1.4
     */
    LOGOUT_INITIATION_SUCCESSFUL,
    /** 
     * Passive authentication failed.
     * @since 1.5
     */
    PASSIVE_FAILED,
}
