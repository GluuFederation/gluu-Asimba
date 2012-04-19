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

import java.io.InterruptedIOException;

import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.helpers.LogLog;
import org.apache.log4j.spi.ErrorHandler;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Error handler which continues logging when an (SQL) error occurs.
 *
 * This error handler is implemented to handle SQL error during event logging.
 * 
 * @author EVB
 * @author Alfa & Ariss
 * @since 1.1
 */
public class JDBCErrorHandler implements ErrorHandler
{

    /**
     * @see org.apache.log4j.spi.ErrorHandler#error(java.lang.String)
     */
    public void error(String message)
    {
        LogLog.error(message);     
    }

    /**
     * @see org.apache.log4j.spi.ErrorHandler#error(
     *  java.lang.String, java.lang.Exception, int)
     */
    public void error(String message, Exception e, int errorCode)
    {
        error(message, e, errorCode, null);              
    }

    /**
     * @see org.apache.log4j.spi.ErrorHandler#error(java.lang.String, 
     *  java.lang.Exception, int, org.apache.log4j.spi.LoggingEvent)
     */
    public void error(String message, Exception e, int i,
        LoggingEvent event)
    {
        if (e instanceof InterruptedIOException || 
            e instanceof InterruptedException) 
        {
            Thread.currentThread().interrupt();
        }
        
        LogLog.error(message, e);        
    }

    /**
     * Not supported
     * @see org.apache.log4j.spi.ErrorHandler#setAppender(
     *  org.apache.log4j.Appender)
     */
    public void setAppender(Appender arg0)
    {
        //Nothing            
    }

    /**
     * Not supported
     * @see org.apache.log4j.spi.ErrorHandler#setBackupAppender(
     *  org.apache.log4j.Appender)
     */
    public void setBackupAppender(Appender arg0)
    {
      //Nothing            
    }

    /**
     * Not supported
     * @see org.apache.log4j.spi.ErrorHandler#setLogger(
     *  org.apache.log4j.Logger)
     */
    public void setLogger(Logger arg0)
    {
        //Nothing            
    }

    /**
     * Not supported
     * @see org.apache.log4j.spi.OptionHandler#activateOptions()
     */
    public void activateOptions()
    {
        //Nothing            
    }        
}

