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
package com.alfaariss.oa.authentication.identifying;

/**
 * Warning enumeration.
 * 
 * This enumeration contains the "user" warnings, which will appear 
 * on the screen if the user makes a mistake. Every warning 
 * in this class can be translated to the corresponding warning
 * text from a resource bundle.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public enum Warnings
{
    /** Invalid user */
    NO_SUCH_USER_FOUND,
    /** Last retry */
    ONE_RETRY_LEFT,

}
