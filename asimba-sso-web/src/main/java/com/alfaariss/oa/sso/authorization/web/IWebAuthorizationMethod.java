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
package com.alfaariss.oa.sso.authorization.web;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.IManagebleItem;
import com.alfaariss.oa.api.authorization.IAuthorizationAction;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;

/**
 * A interface that is implemented by pre authorization method classes.
 *
 * This interface is used by the pre authorization manager in order to verify that the
 * <code>IAuthMethod</code> is of the right type. The way this check is performed now
 * is derived from the fact that most of the functionality that is used for iterating
 * through a profile is similar for pre-authorization and authentication. The code
 * is therefore placed in the <code>AbstractAuthManager</code>, which is therefore
 * not capable of type checking the classes properly. This is done by the concrete
 * manager <code>PreAuthorizationManager</code> using this interface.
 * 
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public interface IWebAuthorizationMethod extends IManagebleItem, IAuthority
{
    /**
     * Attribute name for adding the pretty name as attribute to a 
     * <code>Map</code>, request, session, or application.
     */
    public final static String AUTHZ_METHOD_ATTRIBUTE_NAME = "methodFriendlyName";
    
    /**
     * The method to call for user authorization.
     *
     * @param oRequest The request send by the user.
     * @param oResponse The response to be send back to the user.
     * @param oSession The session the user is associated with.
     * @return resulting user event.
     * @throws OAException when something inrecoverable goes wrong, that would also not
     * validate any of the standard return values. This is most probably due to a severe
     * internal error.
     */
    public UserEvent authorize(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession)
    throws OAException;
    
    /**
     * Start the component.
     * @param oConfigurationManager the configuration manager used to retrieve 
     * the config from the supplied <code>Element</code>. 
     * @param eConfig The configuration section or <code>null</code> if no 
     * configuration is found.
     * @param mapActions Map containing all available actions
     * @throws OAException 
     */
    public void start(IConfigurationManager oConfigurationManager
        , Element eConfig, Map<String,IAuthorizationAction> mapActions) throws OAException;

    /**
     * Stops the component.
     */
    public void stop();
}