/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
package org.asimba.util.saml2.assertion;

import java.io.Serializable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;

/**
 * Base class that implements timestamp validation functionality
 * for working with timestamps within an time-window
 * 
 * Used by/as SAML2IssueInstantWindow, SAML2ConditionsWindow
 * 
 * @author mdobrinic
 *
 */
public class SAML2TimestampWindow implements Serializable {

	/**
	 * Version
	 */
	private static final long serialVersionUID = 4671862655260280506L;


	/**
	 * Local logger instance
	 */
    private Log _oLogger;
    
    
    /**
     * Default before and after values, in milliseconds
     */
    protected final static long DEFAULT_BEFORE_OFFSET = 60000;
    protected final static long DEFAULT_AFTER_OFFSET = 60000;
    
    /**
     * Allowed skew before current time, in milliseconds
     */
    protected long _lBeforeOffset;
    
    /**
     * Allowed skew after current time, in milliseconds
     */
    protected long _lAfterOffset;
    
    
    /**
     * Default constructor uses default settings
     */
    public SAML2TimestampWindow()
    {
        _oLogger = LogFactory.getLog(SAML2TimestampWindow.class);
        
        _lBeforeOffset = DEFAULT_BEFORE_OFFSET;
        _oLogger.info("Using default window 'before offset time' in ms: " + _lBeforeOffset);
        
        _lAfterOffset = DEFAULT_AFTER_OFFSET;
        _oLogger.info("Using default window 'after offset time' in ms: " + _lAfterOffset);
    }
    
    
    /**
     * Constructor that initializes before- and after-values
     * from configuration
     * 
     * Example configuration:
     * <authnstatement>
     *   <window before_offset="3600" after_offset="60" />
     * 
     * @param oConfigManager Configuration manager for reading config
     * @param elConfig Configuration section with settings
     * @throws OAException When something goes really wrong
     */
    public SAML2TimestampWindow(IConfigurationManager oConfigManager, 
        Element elConfig) throws OAException
    {
        _oLogger = LogFactory.getLog(SAML2TimestampWindow.class);
        try
        {
            Element elWindow = oConfigManager.getSection(elConfig, "window");
            if (elWindow == null) {
                _oLogger.error("No 'window' section configured.");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sBefore = oConfigManager.getParam(elWindow, "before_offset");
            if (sBefore == null) {
                _oLogger.error("No 'before_offset' item in 'window' section configured");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sAfter = oConfigManager.getParam(elWindow, "after_offset");
            if (sAfter == null) {
                _oLogger.error("No 'after_offset' item in 'window' section configured");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try {
                _lBeforeOffset = Long.parseLong(sBefore);
                _lBeforeOffset = _lBeforeOffset * 1000;//milliseconds
                
                _lAfterOffset = Long.parseLong(sAfter);
                _lAfterOffset = _lAfterOffset * 1000;//milliseconds

            } catch(NumberFormatException e) {
                _oLogger.error("Invalid before_offset or after_offset configured: " + sBefore + "/" + sAfter);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            // Some integrity checking of the values:
            if (_lBeforeOffset < 0) {
                _oLogger.error("Invalid 'before_offset' item in 'window' section configured, must be > 0: " + sBefore);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            if (_lAfterOffset < 0) {
                _oLogger.error("Invalid 'after_offset' item in 'window' section configured, must be > 0: " + sAfter);
                throw new OAException(SystemErrors.ERROR_INIT);
            }

            _oLogger.info(
                "Using configured window before/after time in ms: " 
                + _lBeforeOffset + "/" + _lAfterOffset);
            
        }
        catch (OAException e) {
            throw e;
        } catch (Exception e) {
            _oLogger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    
    /**
     * Returns the before offset time in milliseconds.
     * @return The before offset time in milliseconds.
     */
    public long getBeforeOffset() {
        return _lBeforeOffset;
    }
    
    /**
     * Sets the before-offset time in milliseconds
     * @param lBeforeOffset the new before-offset time in milliseconds
     */
    public void setBeforeOffset(long lBeforeOffset) {
    	_lBeforeOffset = lBeforeOffset;
    }
    
    /**
     * Returns the after offset time in milliseconds.
     * @return The after offset time in milliseconds.
     */
    public long getAfterOffset() {
        return _lAfterOffset;
    }
    
    /**
     * Sets the after-offset time in milliseconds
     * @param lAfterOffset the new after-offset time in milliseconds
     */
    public void setAfterOffset(long lAfterOffset) {
    	_lAfterOffset = lAfterOffset;
    }

    
    /**
     * Verifies if the supplied time is within the configured time window.
     *
     * @param dateTime The datetime to be verified.
     * @return TRUE if the datetime is within the window.
     */
    public boolean canAccept(DateTime dateTime)
    {
        DateTime dtBefore = new DateTime().minus(_lBeforeOffset);
        DateTime dtAfter = new DateTime().plus(_lAfterOffset);
        
        return (!dateTime.isBefore(dtBefore) && !dateTime.isAfter(dtAfter));
    }
	
}
