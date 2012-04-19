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
package com.alfaariss.oa.util.session;

import java.io.Serializable;

/**
 * Shared attribute names.
 * 
 * Contains shared attribute names for OAS in proxy mode.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ProxyAttributes implements Serializable
{
    private static final long serialVersionUID = 2967540894757725164L;
    
    /** 
     * <b>name:</b> forced_organizations
     * <br>
     * <b>value:</b> <code>Set&lt;String&gt;</code> 
     */
    public final static String FORCED_ORGANIZATIONS = "forced_organizations";
}
