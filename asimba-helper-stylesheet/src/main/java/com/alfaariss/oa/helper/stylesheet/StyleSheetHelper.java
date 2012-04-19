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
package com.alfaariss.oa.helper.stylesheet;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.helper.IHelper;

/**
 * StyleSheet helper.
 * Uses the {@link StyleSheetEngine} to process requests.
 *  
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class StyleSheetHelper implements IHelper, IService
{
    private Log _logger;
    private StyleSheetEngine _engine;
    private String _sID;
    
    /**
     * Constructor.
     */
    public StyleSheetHelper()
    {
        _logger = LogFactory.getLog(StyleSheetHelper.class);
        _engine = new StyleSheetEngine();
    }
    
    /**
     * Initialize the {@link StyleSheetEngine}.
     * 
     * @see IHelper#init(javax.servlet.ServletContext, 
     *  IConfigurationManager, org.w3c.dom.Element)
     */
    public void init(ServletContext context,
        IConfigurationManager configurationManager, Element eStyleSheet)
        throws OAException
    {
        try
        {
            _sID = configurationManager.getParam(eStyleSheet, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
           _engine.start(configurationManager, eStyleSheet, _sID, context);          
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }        
    }
    
    /**
     * Returns the enabled state of the engine.
     * @see com.alfaariss.oa.api.IOptional#isEnabled()
     */
    public boolean isEnabled()
    {
        return _engine.isEnabled();
    }
        
    /**
     * Let the request be processed by the configured handler.
     *
     * If the request could not be processed by the handler or there is no 
     * handler configured then the requestor will be redirected to the default css.
     * @param oRequest the servlet request
     * @param oResponse the servlet response
     * @see IService#service(javax.servlet.http.HttpServletRequest, 
     *  javax.servlet.http.HttpServletResponse)
     */
    public void service(HttpServletRequest oRequest, 
        HttpServletResponse oResponse) throws OAException
    {
        try
        {            
           _engine.process(oRequest, oResponse);
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Error during processing", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }        
    }

    /**
     * Stop the stylesheet engine
     * @see IHelper#destroy()
     */
    public void destroy()
    {
       _engine.stop();
    }
    
    /**
     * Returns the id of the helper.
     *  
     * @return The helper id.
     * @since 1.3
     */
    public String getID()
    {
        return _sID;
    }
}
