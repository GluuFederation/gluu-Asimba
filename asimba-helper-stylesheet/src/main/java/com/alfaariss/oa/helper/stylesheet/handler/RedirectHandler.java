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

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.helper.stylesheet.StyleSheetException;

/**
 * Returns a stylesheet by redirects.
 *
 * @author MHO
 * @author Alfa & Ariss
 */
public class RedirectHandler extends AbstractStyleSheetHandler
{
    private Log _logger;
    
    /**
     * Contructor.
     */
    public RedirectHandler()
    {
        super();
        _logger = LogFactory.getLog(RedirectHandler.class);
    }
    
    /**
     * @see com.alfaariss.oa.helper.stylesheet.handler.AbstractStyleSheetHandler#process(com.alfaariss.oa.api.session.ISession, javax.servlet.http.HttpServletResponse, boolean)
     */
    public void process(ISession session, HttpServletResponse response, boolean isWireless)
        throws StyleSheetException
    {
        try
        {
            String sStyleSheet = super.resolveStyleSheetLocation(session, isWireless);
            if (sStyleSheet != null)
            {
                if (response.isCommitted())
                {
                    _logger.error("Response already committed");
                    throw new StyleSheetException(SystemErrors.ERROR_RESOURCE_CONNECT);
                }
                
                response.sendRedirect(sStyleSheet);
            }
        }
        catch (StyleSheetException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Unable to process request", e);
            throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
