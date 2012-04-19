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

import java.io.Serializable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Object containing functionality to verify the Conditions of a SAML request. 
 * @author MHO
 * @author Alfa & Ariss
 */
public class SAML2ConditionsWindow implements Serializable
{
    /** serialVersionUID */
    private static final long serialVersionUID = 4751285324103071819L;
    private final static long DEFAULT_BEFORE_OFFSET = 60000;
    private final static long DEFAULT_AFTER_OFFSET = 60000;
    private Log _logger;
    private long _lBeforeOffset;
    private long _lAfterOffset;
    
    /**
     * Default constructor using default window.
     */
    public SAML2ConditionsWindow()
    {
        _logger = LogFactory.getLog(SAML2ConditionsWindow.class);
        
        _lBeforeOffset = DEFAULT_BEFORE_OFFSET;
        _logger.info(
            "Using configured IssueInstant window 'before offset time' in ms: " 
            + _lBeforeOffset);
        
        _lAfterOffset = DEFAULT_AFTER_OFFSET;
        _logger.info(
            "Using configured IssueInstant window 'after offset time' in ms: " 
            + _lAfterOffset);
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
        _logger = LogFactory.getLog(SAML2ConditionsWindow.class);
        try
        {
            Element eWindow = configurationManager.getSection(eConfig, "window");
            if (eWindow == null)
            {
                _logger.error("No 'window' section configured for IssueInstant");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sBefore = configurationManager.getParam(eWindow, "before_offset");
            if (sBefore == null)
            {
                _logger.error(
                    "No 'before_offset' item in 'window' section configured for IssueInstant");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                _lBeforeOffset = Long.parseLong(sBefore);
                _lBeforeOffset = _lBeforeOffset * 1000;//milliseconds
            }
            catch(NumberFormatException e)
            {
                _logger.error(
                    "Configured 'before_offset' item in 'window' section configured for IssueInstant is invalid: " 
                    + sBefore, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            if (_lBeforeOffset < 0)
            {
                _logger.error(
                    "Invalid 'before_offset' item in 'window' section configured for IssueInstant is invalid (may not be negative): " 
                    + sBefore);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _logger.info(
                "Using configured IssueInstant window 'before offset time' in ms: " 
                + _lBeforeOffset);
            
            String sAfter = configurationManager.getParam(eWindow, "after_offset");
            if (sAfter == null)
            {
                _logger.error(
                    "No 'after_offset' item in 'window' section configured for IssueInstant");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                _lAfterOffset = Long.parseLong(sAfter);
                _lAfterOffset = _lAfterOffset * 1000;//milliseconds
            }
            catch(NumberFormatException e)
            {
                _logger.error(
                    "Configured 'after_offset' item in 'window' section configured for IssueInstant is invalid: " 
                    + sAfter, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            if (_lBeforeOffset < 0)
            {
                _logger.error(
                    "Invalid 'after_offset' item in 'window' section configured for IssueInstant is invalid (may not be negative): " 
                    + sAfter);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _logger.info(
                "Using configured IssueInstant window 'after offset time' in ms: " 
                + _lAfterOffset);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns the before offset time in milliseconds.
     * @return The before offset time in milliseconds.
     */
    public long getBeforeOffset()
    {
        return _lBeforeOffset;
    }
    
    /**
     * Returns the after offset time in milliseconds.
     * @return The after offset time in milliseconds.
     */
    public long getAfterOffset()
    {
        return _lAfterOffset;
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
    
    /**
     * Verifies if the current time is before the AuthnInstant time.
     * @param dtAuthnInstant AuthnInstant
     * @return TRUE if supplied AuthnInstant is before the current time
     */
    public boolean canAccept(DateTime dtAuthnInstant)
    {
        DateTime dtNow = new DateTime().minus(_lBeforeOffset);
        return (dtNow.isAfter(dtAuthnInstant));
    }
}

