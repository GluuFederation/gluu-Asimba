
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
package com.alfaariss.oa.api;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.helper.IHelper;
import com.alfaariss.oa.api.profile.IRequestorProfile;

/**
 * Interface for services such as requestor profiles or helpers.
 * 
 * Services can be called by an {@link HttpServlet} to perform the actual 
 * processing of an HTTP request.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 * @see IHelper
 * @see IRequestorProfile
 */
public interface IService
{
      
    /**
     * Process a {@link HttpServlet} request.
     * @param oServletRequest The request.
     * @param oServletResponse The response.
     * @throws OAException If processing fails due to internal error.
     */
    public void service(HttpServletRequest oServletRequest,
        HttpServletResponse oServletResponse) throws OAException;
}
