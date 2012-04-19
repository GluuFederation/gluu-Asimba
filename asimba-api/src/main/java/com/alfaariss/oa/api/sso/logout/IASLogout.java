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
package com.alfaariss.oa.api.sso.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.tgt.ITGT;

/**
 * Interface that can be implemented by Authentication Methods to add 
 * asynchronous logout support.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public interface IASLogout
{
    /**
     * Retrieve the ID.
     * @return The ID of the item.
     */
    public String getID();
    
    /**
     * Verifies if the TGT can be loggedout by this method.
     *   
     * @param tgt The TGT of the user.
     * @return TRUE if the TGT requires to be loggedout by this method.
     * @throws OAException If an internal error occurred during verification.
     */
    public boolean canLogout(ITGT tgt) throws OAException;
    
    /**
     * Performs the asynchronous logout at the remote IDP (organization).
     * 
     * @param oRequest The servlet request.
     * @param oResponse The servlet response.
     * @param tgt The TGT to be loggedout.
     * @param session The logout session.
     * @return The logout event.
     * @throws OAException If sending the logout request fails.
     */
    public UserEvent logout(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ITGT tgt, ISession session) throws OAException;
}
