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
package com.alfaariss.oa.engine.core.attribute.gather;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor;


/**
 * The Attribute gather.
 *
 * Calls all <code>IProcessor</code> components.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class AttributeGatherer implements IComponent, IProcessor
{
    private static Log _logger = LogFactory.getLog(AttributeGatherer.class);  
    
    private final List<IProcessor> _listProcessors;
    private boolean _bEnabled;
    private IConfigurationManager _configurationManager;
    private String _sID;
    private String _sFriendlyName;
    
	/**
	 * Create new <code>AttributeGatherer</code>.
	 */
	public AttributeGatherer()
    {
        _listProcessors = new Vector<IProcessor>();
        _bEnabled = false;
	}

	/**
     * Gather attributes with input from the processors components.
     * 
     * The processor components will update the attributes object sequentially, 
     * so the last processor component is leading.
     * @param sUserId the user id for who the attributes must be gathered
     * @param oAttributes the attributes object that will be updated
     * @throws AttributeException if gathering fails
     */
    public void process(String sUserId, IAttributes oAttributes) throws AttributeException
    {
        if (_bEnabled)
        {
            for(IProcessor processor : _listProcessors)
            {
               processor.process(sUserId, oAttributes); 
            }
        }
    }

    /**
	 * Create processors and add them to the processors list.
     * 
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws AttributeException
    {
        try
        {
            _configurationManager = oConfigurationManager;
            _bEnabled = true;
            String sEnabled = _configurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " + sEnabled);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            _sID = _configurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = _configurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eProcessor = _configurationManager.getSection(eConfig, "processor");
            //DD there can be zero or more processors configured
            while (eProcessor != null)
            {
                IProcessor oProcessor = getProcessor(eProcessor);
                oProcessor.start(_configurationManager, eProcessor);
                _listProcessors.add(oProcessor);
                eProcessor = _configurationManager.getNextSection(eProcessor);
            }
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialize", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL, e);
        }
	}

    /**
     * Stop and starts the attribute gatherer.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            stop();
            start(_configurationManager, eConfig);
        }
    }
    
	/**
	 * Stop all processors and clean the processor list.
	 * @see com.alfaariss.oa.api.IComponent#stop()
	 */
	public void stop()
    {
        if (_bEnabled)
        {
            _bEnabled = false;
            
    	    for(IProcessor processor : _listProcessors)
            {
                processor.stop(); 
            }
            
            _listProcessors.clear();
        }
	}

	/**
	 * @see com.alfaariss.oa.api.IManagebleItem#getID()
	 */
	public String getID()
    {
        return _sID;
    }

    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * Check if the <code>AttributeGatherer</code> is enabled.
     * @see com.alfaariss.oa.api.IOptional#isEnabled()
     */
    public boolean isEnabled()
    {
    	return _bEnabled;
    }

    private IProcessor getProcessor(Element eConfig) throws AttributeException
    {
        IProcessor oProcessor = null;
        try
        {
            String sClass = _configurationManager.getParam(eConfig, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' item in 'processor' section found");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                oProcessor = (IProcessor)Class.forName(sClass).newInstance();
            }
            catch (InstantiationException e)
            {
                _logger.error("Can't create an instance of the configured class: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
            }
            catch (IllegalAccessException e)
            {
                _logger.error("Configured class can't be accessed: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
            }
            catch (ClassNotFoundException e)
            {
                _logger.error("Configured class doesn't exist: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
            }
            catch (ClassCastException e)
            {
                _logger.error("Configured class isn't of type 'IProcessor': " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
            }
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during processor creation", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL, e);
        }
        return oProcessor;
    }

}