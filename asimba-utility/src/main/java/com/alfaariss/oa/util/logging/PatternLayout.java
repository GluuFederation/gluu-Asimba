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
package com.alfaariss.oa.util.logging;

/**
 * Log4J Layout for debug logger.
 *
 * Wraps the Log4J <code>PatternLayout</code>. 
 * Log4J log4j-1.2.14 bug 9349:
 * <code>
 * WriterAppender line 164
 *   if(super.layout.ignoresThrowable()) 
 * Should be:
 *   if(!super.layout.ignoresThrowable())
 * </code>
 * @author EVB
 * @author Alfa & Ariss
 *
 * @see <a href="http://issues.apache.org/bugzilla/show_bug.cgi?id=9349">
 *  issues.apache.org</a>
 */
public class PatternLayout extends org.apache.log4j.PatternLayout
{
    
     /**
     * Do not write throwables outside this format. 
     * @see org.apache.log4j.PatternLayout#ignoresThrowable()
     */
    public boolean ignoresThrowable()
     {
         return false;
     }
}

