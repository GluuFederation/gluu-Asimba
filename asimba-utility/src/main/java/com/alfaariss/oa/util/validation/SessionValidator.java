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
package com.alfaariss.oa.util.validation;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class to validate session related objects.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class SessionValidator
{
    /**
     * The validation pattern for session ID's.
     */
    public static final Pattern ID_PATTERN = Pattern.compile("[A-Za-z0-9-_]{22,24}");
    
    /**
     * Validate a Modified Base64 encoded session id.
     * @param sId The id to be validated.
     * @return <code>true</code> if the given id is not <code>null</code> 
     *  and it matches  {@link SessionValidator#ID_PATTERN}.
     */
    public static boolean validateDefaultSessionId(String sId)
    {
        if(sId == null)
            return false;
        Matcher m = ID_PATTERN.matcher(sId);
        return m.matches();    
    }
}
