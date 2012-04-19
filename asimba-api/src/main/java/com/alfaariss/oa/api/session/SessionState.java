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
package com.alfaariss.oa.api.session;

/**
 * Contains all states of the authentication process.
 * 
 * @author EVB
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public enum SessionState
{
    /**
     * New authentication session.
     */
    SESSION_CREATED,
    /**
     * Pre-authorization in progress.
     */
    PRE_AUTHZ_IN_PROGRESS,
    /**
     * Pre-authorization succesfully completed.
     */
    PRE_AUTHZ_OK,
    /**
     * Pre-authorization failed: no access.
     */
    PRE_AUTHZ_FAILED,
    /**
     * Post-authorization in progress.
     */
    POST_AUTHZ_IN_PROGRESS,
    /**
     * Post-authorization succesfully completed.
     */
    POST_AUTHZ_OK,
    /**
     * Post-authorization failed: no access.
     */
    POST_AUTHZ_FAILED,
    /**
     * Authentication selection in progress.
     */
    AUTHN_SELECTION_IN_PROGRESS,
    /**
     * Authentication selection succesfully completed.
     */
    AUTHN_SELECTION_OK,
    /**
     * Authentication selection failed.
     */
    AUTHN_SELECTION_FAILED,
    /**
     * Authentication in progress.
     */
    AUTHN_IN_PROGRESS,    
    /**
     * Authentication succesfully completed.
     */
    AUTHN_OK,
    /**
     * Authentication failed.
     */
    AUTHN_FAILED,
    /**
     * Authentication method not supported.
     */
    AUTHN_NOT_SUPPORTED,
    /**
     * User not found.
     */
    USER_UNKNOWN, 
    /**
     * User not enabled.
     */
    USER_BLOCKED, 
    /**
     * Authentication successfully completed, user cancelled.
     */
    USER_CANCELLED,
    /**
     * User logout was successfull.
     * @since 1.4
     */
    USER_LOGOUT_SUCCESS,
    /**
     * User is logging out.
     * @since 1.4
     */
    USER_LOGOUT_IN_PROGRESS,
    /**
     * User logout failed.
     * @since 1.4
     */
    USER_LOGOUT_FAILED,
    /**
     * Partial user logout.
     * @since 1.4
     */
    USER_LOGOUT_PARTIAL,
    /**
     * Passive logout failed.
     * @since 1.5
     */    
    PASSIVE_FAILED,
}
