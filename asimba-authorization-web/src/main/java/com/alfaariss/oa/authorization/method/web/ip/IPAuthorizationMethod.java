/*
 * * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authorization.method.web.ip;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.authorization.IAuthorizationAction;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.authorization.method.web.AbstractWebAuthorizationMethod;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.util.logging.UserEventLogItem;

/**
 * Allows or denies access depending on user's IP address.
 *
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public class IPAuthorizationMethod extends AbstractWebAuthorizationMethod
{
    private final static String AUTHORITY_NAME = "IPAuthZMethod_";
    private Log _logger;
    private Log _eventLogger;
    private List<IPAuthRange> _lRanges = null;
    private boolean _bMatch = true;

    /**
     * Constructor
     */
    public IPAuthorizationMethod()
    {
        _logger = LogFactory.getLog(IPAuthorizationMethod.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
    }
    
    /**
     * DD A minimum of one configured 'range' section is needed
     * @see AbstractWebAuthorizationMethod#start(IConfigurationManager, 
     *  org.w3c.dom.Element, java.util.Map)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig, Map<String,IAuthorizationAction> mapActions) throws OAException
    {
        super.start(oConfigurationManager, eConfig, mapActions);
        _logger.debug("Authorization method '" + getID() + "' starting...");
        
        _lRanges = new LinkedList<IPAuthRange>();
  
        Element eRanges = _configManager.getSection(eConfig, "ranges");
        if (eRanges == null)
        {
            _logger.error("No 'ranges' section found in configuration for method: " + getID());
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        String sValue = _configManager.getParam(eRanges, "match");
        if ("true".equalsIgnoreCase(sValue) || "false".equalsIgnoreCase(sValue)) 
        {
            _bMatch = new Boolean(sValue);
            
            StringBuffer sbInfo = new StringBuffer("Default value for IP authorization set to ");
            sbInfo.append(_bMatch);
            sbInfo.append(" in authorization method: ");
            sbInfo.append(getID());
            
            _logger.info(sbInfo.toString());
        } else {
            _logger.error(
                "Misconfigured property 'match' for IP authorization method " + getID());
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        Element eOneRange = _configManager.getSection(eRanges, "range");
        while (eOneRange != null)
        {         
            String sStart = _configManager.getParam(eOneRange, "start");
            if (sStart == null)
            {
                _logger.error("Misconfigured property 'start' for IP authorization method " + getID());
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sEnd = _configManager.getParam(eOneRange, "end");
            if (sEnd == null)
            {
                _logger.error("Misconfigured property 'end' for IP authorization method " + getID());
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                IPAuthRange oRange = new IPAuthRange(sStart, sEnd);
                _lRanges.add(oRange);
            }
            catch (OAException aee)
            {
                _logger.error("Misconfigured IP value for IP authorization method " + getID());
                throw aee;
            }
            
            eOneRange = _configManager.getNextSection(eOneRange);
        }

        if (_lRanges.isEmpty())
        {
            _logger.error("Not even one 'range' section found in 'ranges' section in configuration for method: " + getID());
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _logger.info("IP Authorization method loaded properly: " + getID());
    }

    /**
     * DD The first range that matches will decide if the method succeeds or fails
     * @see com.alfaariss.oa.sso.authorization.web.IWebAuthorizationMethod#authorize(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, com.alfaariss.oa.api.session.ISession)
     */
    public UserEvent authorize(HttpServletRequest request,
        HttpServletResponse response, ISession session) throws OAException
    {
        UserEvent event = UserEvent.AUTHZ_METHOD_SUCCESSFUL;
        if (request == null)
            throw new IllegalArgumentException("Supplied request == null");
        if (response == null)
            throw new IllegalArgumentException("Supplied response == null");
        if (session == null)
            throw new IllegalArgumentException("Supplied session == null");
        
        String sUserIP = request.getRemoteAddr();
        
        boolean bInrange = false;
        for (IPAuthRange oRange : _lRanges)
        {          
            bInrange = oRange.matchRange(sUserIP);   
            if(bInrange)
                break;
        }
        
        //in range? match   result
        //--------------------------
        // false    false   true
        // false    true    false
        // true     false   false
        // true     true    true
        if (!( bInrange ^ _bMatch))
        {
            event = _oAction.perform(session);
        }    
        
        _eventLogger.info(new UserEventLogItem(session, 
            request.getRemoteAddr(), event, 
            this, null));
        
        return event;
    }
    
    /**
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sId;
    }
    
    /**
     * @see com.alfaariss.oa.authorization.method.web.AbstractWebAuthorizationMethod#stop()
     */
    public void stop()
    {
        if (_lRanges != null)
            _lRanges.clear();
        
        super.stop();
    }

    private class IPAuthRange
    {
        private long _aiStart = 0;
        private long _aiEnd = 0;
        
        /**
         * Create new IP range definition object.
         *
         * @param start Start of range.
         * @param end End of range.
         * @throws OAException If start or end is not properly defined.
         */
        public IPAuthRange(String start, String end) throws OAException
        {
            _aiStart = setIp(start);
            _aiEnd = setIp(end);
        }
        
        /**
         * Checks if the supplied ip matches a range.
         * @param ip user IP address
         * @return TRUE if supplied ip matches the criteria
         * @throws OAException if matching fails
         */
        public boolean matchRange(String ip) throws OAException
        {
            return isInRange(ip);
        }
        
        /**
         * Defines whether the ip address is within the specified range.
         *
         * @param ip The IP address.
         * @return boolean true if the ip address is within the specified range.
         * @throws OAException if the parameter is not a valid ip address.
         */
        private boolean isInRange(String ip) throws OAException
        {
            assert ip != null;
            
            long iCheckedIp = setIp(ip);
            
            if (_aiStart <= iCheckedIp && iCheckedIp <= _aiEnd)
            {
                return true;
            }
            
            return false;
        }
        
        private long setIp (String ip) throws OAException
        {
            assert ip != null;
            
            String[] asStartParts = ip.split("\\.");
            long iRetVal = 0;
            
            if (asStartParts.length == 4) {
                for (int i = 0; i < 4; i++) {
                    try {
                        int iVal = Integer.parseInt(asStartParts[i]);
                        
                        long power = (long)Math.pow(2, 8*(3-i));
                        
                        iRetVal += iVal * power;
                    } catch (NumberFormatException nfe) {
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ, nfe);
                    }   
                }
            }
            else
            {
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            return iRetVal;
        }
    }

}
