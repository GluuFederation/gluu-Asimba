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
package com.alfaariss.oa.sso.authentication.service;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.IManagebleItem;
import com.alfaariss.oa.api.logging.IAuthority;

/**
 * An interface that can be implemented by authentication method classes.
 *
 * If this interface is implemented the authentication method can be used for 
 * non web sso authentication.
 * 
 * @author MHO
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public interface IServiceAuthenticationMethod extends IManagebleItem, IComponent, IAuthority
{
    /**
     * Authenticates a user with the supplied credentials.
     * 
     * @param sUserID the user id
     * @param baCredentials the credentials, a password or certificate or something
     * @return UserEvent The user event
     * @throws OAException if authentication fails
     */
    public UserEvent authenticate(String sUserID, byte[] baCredentials) throws OAException;
}
