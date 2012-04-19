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
package com.alfaariss.oa.util.ldap;

/**
 * Utility class to escape LDAP special chars.
 * <br>
 * This utility functionality can be used to prevent LDAP insertions. 
 * 
 * <br><br><i>Includes code from OWASP (www.owasp.org).</i>
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class JNDIUtil
{

    /**
     * Escape LDAP special characters in DN.
     * 
     * Escapes characters from RFC 2253 and the '/' character for JNDI
     * 
     * @param name The DN
     * @return The escaped name.
     * @see <a href="http://tools.ietf.org/html/rfc2253" target="_new">
     *  UTF-8 String Representation of Distinguished Names</a>
     */
    public static String escapeDN(String name)
    {
        StringBuffer sb = new StringBuffer();
        if ((name.length() > 0)
            && ((name.charAt(0) == ' ') || (name.charAt(0) == '#')))
        {
            //add the leading backslash if needed
            sb.append('\\'); 
        }
        for (int i = 0; i < name.length(); i++)
        {
            char curChar = name.charAt(i);
            switch (curChar)
            {
                case '\\':
                {
                    sb.append("\\\\");
                    break;
                }
                case ',':
                {
                    sb.append("\\,");
                    break;
                }
                case '+':
                {
                    sb.append("\\+");
                    break;
                }
                case '"':
                {
                    sb.append("\\\"");
                    break;
                }
                case '<':
                {
                    sb.append("\\<");
                    break;
                }
                case '>':
                {
                    sb.append("\\>");
                    break;
                }
                case ';':
                {
                    sb.append("\\;");
                    break;
                }
                default:
                {
                    sb.append(curChar);
                    break;
                }
            }
        }
        if ((name.length() > 1) && (name.charAt(name.length() - 1) == ' '))
        {
            //add the trailing backslash if needed
            sb.insert(sb.length() - 1, '\\');
        }
        return sb.toString();
    }

    /**
     * Escape LDAP special characters in search filter.
     * 
     * Escapes characters from RFC 2254 and the '/' character for JNDI
     * 
     * @param filter search filter
     * @return escaped search filter
     * @see <a href="http://tools.ietf.org/html/rfc2254" target="_new">
     *  The String Representation of LDAP Search Filters</a>
     */
    public static final String escapeLDAPSearchFilter(String filter)
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < filter.length(); i++)
        {
            char c = filter.charAt(i);
            switch (c)
            {
                case '\\':
                {
                    sb.append("\\5c");
                    break;
                }
                case '*':
                {
                    sb.append("\\2a");
                    break;
                }
                case '(':
                {
                    sb.append("\\28");
                    break;
                }
                case ')':
                {
                    sb.append("\\29");
                    break;
                }
                case '\u0000':
                {
                    sb.append("\\00");
                    break;
                }
                default:
                {
                    sb.append(c);
                    break;
                }
            }
        }
        return sb.toString();
    }

}
