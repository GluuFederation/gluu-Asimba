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
package com.alfaariss.oa;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.engine.core.EngineLauncher;

/**
 * Manages the Engine component by using the Launcher functionality.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ManagerServlet extends HttpServlet
{
    private static final long serialVersionUID = -524782026223202293L;
    
    private static Log _logger;
    private EngineLauncher _oEngineLauncher;
    
    /**
     * Initializes the Servlet.
     * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
     */
    public void init(ServletConfig oServletConfig) throws ServletException
    {
        try
        {
            super.init(oServletConfig);
            _logger = LogFactory.getLog(ManagerServlet.class);
            _oEngineLauncher = new EngineLauncher();
        }
        catch (Exception e)
        {
            _logger.fatal("Initialization failed", e);
        }
    }

    /**
     * Handles requests send by the system manager.
     * 
     * The following requests are supported at this moment:
     * <ul>
     * <li>do=restart</li>
     * <li>do=stop</li>
     * <li>do=start</li>
     * </ul>
     * @see javax.servlet.http.HttpServlet#service(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */     
    public void service(HttpServletRequest oRequest, 
        HttpServletResponse oResponse) throws ServletException, IOException
    {
        try
        {
            Properties pConfig = cloneConfigurationFromRequest(oRequest);           
            String sDo = oRequest.getParameter("do");
            if (sDo == null) //No 'do' paramater
            {
                String sGet = oRequest.getParameter("get");
                if (sGet == null) //No 'get' and no 'do' paramater
                {
                    _logger.error("Invalid request sent from IP: " + oRequest.getRemoteAddr());
                    oResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
                }                
                else
                {
                    StringBuffer sbWarning = new StringBuffer("Invalid request with name: ");
                    sbWarning.append(sGet);
                    sbWarning.append(", sent from IP: ");
                    sbWarning.append(oRequest.getRemoteAddr());
                    _logger.error(sbWarning.toString());
                    oResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
                }
               
            }
            else if (sDo.equals("restart"))
            {
                _logger.info("Performing restart request sent from IP: " 
                    + oRequest.getRemoteAddr());
                _oEngineLauncher.restart(pConfig);
            }
            else if (sDo.equals("stop"))
            {
                _logger.info("Performing stop request sent from IP: " 
                    + oRequest.getRemoteAddr());
                _oEngineLauncher.stop();
            }
            else if (sDo.equals("start"))
            {
                _logger.info("Performing start request sent from IP: " 
                    + oRequest.getRemoteAddr());
                _oEngineLauncher.start(pConfig);
            }            
            else
            {
                StringBuffer sbWarning = new StringBuffer("Invalid request with name: ");
                sbWarning.append(sDo);
                sbWarning.append(", sent from IP: ");
                sbWarning.append(oRequest.getRemoteAddr());
                _logger.error(sbWarning.toString());
                oResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
            
            if (!oResponse.isCommitted())
                oResponse.sendError(HttpServletResponse.SC_OK);
        }
        catch(OAException e)
        {
            _logger.error("Error processing request", e);
            
            _logger.debug("try stopping the server");
            _oEngineLauncher.stop();
            
            if (!oResponse.isCommitted())
                oResponse.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error", e);
            
            _logger.debug("try stopping the server");
            _oEngineLauncher.stop();
            
            if (!oResponse.isCommitted())
                oResponse.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
    
    /**
     * destroys the Servlet.
     * @see javax.servlet.Servlet#destroy()
     */
    public void destroy()
    {
        try
        {
            super.destroy();
            _logger.info("Stopped: Manager Servlet");
        }
        catch (Exception e)
        {
            _logger.fatal("Could not destroy Manager Servlet", e);
        }
    }

    //Clone the request parameters to a properties object
    private Properties cloneConfigurationFromRequest(HttpServletRequest oRequest)
    {
        Properties configuration = new Properties();
        Enumeration keys = oRequest.getParameterNames();
        while(keys.hasMoreElements())
        {
              String key = (String)keys.nextElement();
              String value = oRequest.getParameter(key);
              configuration.put(key, value);
        }
        return configuration;
    }
}