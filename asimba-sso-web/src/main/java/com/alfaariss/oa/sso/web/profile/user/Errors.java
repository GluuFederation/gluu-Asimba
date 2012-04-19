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
package com.alfaariss.oa.sso.web.profile.user;

/**
 * Error enumeration.
 * 
 * This enumeration contains the "user" errors, which will appear 
 * on the screen if the user makes a mistake. Every warning 
 * in this class can be translated to the corresponding error
 * text from a resource bundle.
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public enum Errors
{
    /** No TGT */
    NO_TGT,
    
    /** Invalid request */
    INVALID_REQUEST
}
