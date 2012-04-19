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
 * Utility class to validate country and language codes.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class LocaleValidator
{
    /**
     * The validation pattern for country and language codes.
     */
    public static final Pattern LOCALE_PATTERN = Pattern.compile("[A-Za-z]{2,3}");
    
    /**
     * Validate a language code.
     * @param code The language code to be validated.
     * @return <code>true</code> if the supplied code is not <code>null</code> 
     *  and it matches  {@link LocaleValidator#LOCALE_PATTERN}.
     */
    public static boolean validateLanguage(String code)
    {
        if(code == null)
            return false;
        Matcher m = LOCALE_PATTERN.matcher(code);
        return m.matches();    
    }
    
    /**
     * Validate a country code.
     * @param code The country code to be validated.
     * @return <code>true</code> if the supplied code is not <code>null</code> 
     *  and it matches  {@link LocaleValidator#LOCALE_PATTERN}.
     */
    public static boolean validateCountry(String code)
    {
        if(code == null)
            return false;
        Matcher m = LOCALE_PATTERN.matcher(code);
        return m.matches();    
    }
}
