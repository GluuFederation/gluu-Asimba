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
package com.alfaariss.oa.helper.stylesheet.handler;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.helper.stylesheet.StyleSheetException;

/**
 * Returns a stylesheet by streaming the full css document.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class StreamHandler extends AbstractStyleSheetHandler
{
    private static final String CHARSET = "UTF-8";
    private Log _logger; 
    
    /**
     * Constructor.
     */
    public StreamHandler()
    {
        super();
        _logger = LogFactory.getLog(StreamHandler.class);
    }
    

    /**
     * @see com.alfaariss.oa.helper.stylesheet.handler.AbstractStyleSheetHandler#process(com.alfaariss.oa.api.session.ISession, javax.servlet.http.HttpServletResponse, boolean)
     */
    public void process(ISession session, HttpServletResponse response, boolean isWireless)
        throws StyleSheetException
    {
        BufferedReader streamInput = null;
        ServletOutputStream responseOutputStream = null;
        try
        {
            String sStyleSheet = super.resolveStyleSheetLocation(session, isWireless);
            if (sStyleSheet != null)
            {
                URL oURL = new URL(sStyleSheet);
                streamInput = new BufferedReader(new InputStreamReader(oURL.openStream()));
                
                responseOutputStream = response.getOutputStream();
                
                String sInput = null;
                while ((sInput = streamInput.readLine()) != null)
                {
                    sInput += "\r\n";
                    responseOutputStream.write(sInput.getBytes(CHARSET));
                }
            }
        }
        catch (Exception e)
        {
            _logger.error("Could not stream stylesheet", e);
            throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (responseOutputStream != null)
                {
                    responseOutputStream.flush(); 
                    responseOutputStream.close();                   
                }
            }
            catch (Exception e)
            {
                _logger.error("Could not close output stream", e);
            }
            
            try
            {
                if (streamInput != null)
                    streamInput.close();                   
            }
            catch (Exception e)
            {
                _logger.error("Could not close input stream", e);
            }
            
        }
        
    }
}
