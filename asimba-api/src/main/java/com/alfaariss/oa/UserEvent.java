
/*
 * Asimba Server
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
package com.alfaariss.oa;

/**
 * All user events.
 * 
 * @author EVB
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public enum UserEvent
{
    /**
     * Internal error.
     * If an internal error occurs during client (e.g. user) interaction. 
     */
    INTERNAL_ERROR,
    
    /**
     * Request invalid.
     */
    REQUEST_INVALID,
    
    /**
     * Session invalid.
     */
    SESSION_INVALID, 
 
    /**
     * Session expired.
     */
    SESSION_EXPIRED,
    
    /**
     * Invalid Ticket Granting Ticket: not sufficient.
     */
    TGT_NOT_SUFFICIENT,
    
    /**
     * Invalid user in Ticket Granting Ticket.
     */
    TGT_USER_INVALID,
 
    /**
     * Discovery of user information (endpoint) successful.
     */
    USER_IDENTIFIED, 
 
    /**
     * User updated in internal db.
     */
    USER_UPDATED,
    
    /**
     * User added to internal db.
     */
    USER_ADDED,
    
    /**
     * User removed from internal db.
     */
    USER_REMOVED,
    
    /**
     * User blocked.
     */
    USER_BLOCKED,
    
    /**
     * User unknown.
     */
    USER_UNKNOWN,
 
    /**
     * User not enabled.
     */
    USER_DISABLED,
    
    /**
    * User cancelled.
    */
    USER_CANCELLED,
    
    /**
     * Pre Authorization Profile successful.
     */
    USER_PRE_AUTHORIZED,

    /**
     * Post Authorization Profile successful.
     */
    USER_POST_AUTHORIZED,
    
    /**
     * Authentication by authentication profile or SSO successful.
     */
    USER_AUTHENTICATED,
    
    /**
     * User successfully logged out
     */
    USER_LOGGED_OUT,      
   
    /**
     * Authentication profile disabled.
     * <br>
     * The Authentication profile contains several authentication methods.
     */
    AUTHN_PROFILE_DISABLED,
    
    /**
     * Invalid authentication profile.
     */
    AUTHN_PROFILE_INVALID,
 
    /**
     * No profiles available (e.g. after fallback).
     */
    AUTHN_PROFILE_NOT_AVAILABLE, 
    
    /**
     * Authentication selection successful.
     */
    AUTHN_PROFILE_SELECTED,
    
    /**
     * Authentication method not supported for user.
     */
    AUTHN_METHOD_NOT_SUPPORTED,
 
    /**
     * Authentication method not registered for user.
     */
    AUTHN_METHOD_NOT_REGISTERED,
    
    /**
     * Authentication method not finished.
     * <br>
     * When user input is required.
     */
    AUTHN_METHOD_IN_PROGRESS,
    
    /**
     * Authentication method successfully finished.
     */
    AUTHN_METHOD_SUCCESSFUL,
    
    /**
     * Authentication method failed.
     */
    AUTHN_METHOD_FAILED,
 
    /**
     * Authorization Profile disabled.
     */
    AUTHZ_PROFILE_DISABLED, 
    
    /**
     * Authorization method not finished.
     * <br>
     * When user input is required.
     */
    AUTHZ_METHOD_IN_PROGRESS,
    
    /**
     * Authorization method successfully finished.
     */
    AUTHZ_METHOD_SUCCESSFUL,
    
    /**
     * Authorization method failed.
     */
    AUTHZ_METHOD_FAILED,
    /**
     * Ticket Granting Ticket expired.
     * @since 1.3
     */
    TGT_EXPIRED,
    
    /**
     * User logout failed
     * @since 1.4
     */
    USER_LOGOUT_FAILED,   
    /**
     * User logout in progress
     * @since 1.4
     */
    USER_LOGOUT_IN_PROGRESS,  
    /**
     * User was only partially loggedout
     * @since 1.4
     */
    USER_LOGOUT_PARTIALLY,  
}
