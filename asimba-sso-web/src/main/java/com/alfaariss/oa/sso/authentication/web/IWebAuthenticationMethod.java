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
package com.alfaariss.oa.sso.authentication.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.IManagebleItem;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;

/**
 * An interface that is implemented by authentication method classes.
 *
 * If this interface is implemented the authentication method can be used for 
 * web sso authentication.
 * 
 * @author MHO
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public interface IWebAuthenticationMethod extends IManagebleItem, IComponent, IAuthority
{
    
    /**
     * Attribute name for adding the pretty name as attribute to a 
     * <code>Map</code>, request, session, or application.
     */
    public final static String AUTHN_METHOD_ATTRIBUTE_NAME = "methodFriendlyName";
    
    /**
     * Attribute name for adding the user ID as attribute to a 
     * <code>Map</code>, request, session, or application.
     */
    public final static String USERID_ATTRIBUTE_NAME = "user_id";
    
    /**
     * Attribute name for adding retries as attribute to a 
     * <code>Map</code>, request, session, or application.
     */
    public final static String RETRIES_ATTRIBUTE_NAME = "retries";
    
    /**
     * Session attribute name that indicates whether SSO for this
     * method should be disabled
     */
    public final static String DISABLE_SSO = "disable_sso";
    
    /**
     * Authenticates and identifies a user. 
     * 
     * @param oRequest The request send by the user.
     * @param oResponse The response to be send back to the user.
     * @param oSession The session the user is associated with.
     * @return The user event.
     * @throws OAException if authentication fails
     */
    public UserEvent authenticate(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession)
    throws OAException;
}
