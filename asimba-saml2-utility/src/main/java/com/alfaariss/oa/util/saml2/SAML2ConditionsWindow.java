/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.util.saml2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.assertion.SAML2TimestampWindow;
import org.joda.time.DateTime;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Object containing functionality to verify the Conditions of a SAML request. 
 * @author MHO
 * @author Alfa & Ariss
 */
public class SAML2ConditionsWindow extends SAML2TimestampWindow
{
    /** serialVersionUID */
    private static final long serialVersionUID = 4751285324103071819L;

    private Log _logger;
    
    /**
     * Default constructor using default window.
     */
    public SAML2ConditionsWindow()
    {
        super();
        _logger = LogFactory.getLog(SAML2ConditionsWindow.class);
    }
    /**
     * Constructor using configurable window.
     * 
     * @param configurationManager The configuration manager
     * @param eConfig The config section for this object
     * @throws OAException If configuration is invalid
     */
    public SAML2ConditionsWindow (IConfigurationManager configurationManager, 
        Element eConfig) throws OAException
    {
    	super(configurationManager, eConfig);
    }
    
    /**
     * Verifies if the current time is within the supplied time window.
     * <br>
     * The time window is extended with configured offsets.
     * 
     * @param dtNB Not Before condition or NULL if not available.
     * @param dtNOA Not On Or After condition or NULL if not available.
     * @return TRUE if the current datetime is within the window.
     */
    public boolean canAccept(DateTime dtNB, DateTime dtNOA)
    {
        DateTime dtNow = new DateTime();
        
        if (dtNB != null)
        {
            DateTime dtNotBefore = dtNB.minus(_lBeforeOffset);
            if (dtNow.getMillis() < dtNotBefore.getMillis())
            {
                StringBuffer sbDebug = new StringBuffer("Condition time stamp(s) incorrect; Current time (");
                sbDebug.append(dtNow);
                sbDebug.append(") is before the Not Before time: ");
                sbDebug.append(dtNB);
                _logger.debug(sbDebug.toString());
                return false;
            }
        }
        
        if (dtNOA != null)
        {
            DateTime dtNotOnOrAfter = dtNOA.plus(_lAfterOffset);
            if(dtNow.getMillis() >= dtNotOnOrAfter.getMillis())
            {
                StringBuffer sbDebug = new StringBuffer("Condition time stamp(s) incorrect; Current time (");
                sbDebug.append(dtNow);
                sbDebug.append(") is on or after the Not On Or After time: ");
                sbDebug.append(dtNOA);
                _logger.debug(sbDebug.toString());
                return false;
            }
        }
        
        return true;
    }
}

