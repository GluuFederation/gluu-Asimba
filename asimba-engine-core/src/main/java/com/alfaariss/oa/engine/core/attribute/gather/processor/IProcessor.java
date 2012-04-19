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
package com.alfaariss.oa.engine.core.attribute.gather.processor;

import org.w3c.dom.Element;

import com.alfaariss.oa.api.IManagebleItem;
import com.alfaariss.oa.api.IOptional;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;

/**
 * The interface for Attribute processors.
 *
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IProcessor extends IManagebleItem, IOptional
{
    /**
     * Starts the processor with it's configuration section.
     *
     * @param oConfigurationManager the configuration manager needed to read 
     * the configuration
     * @param eConfig the configuration section for this gatherer
     * @throws AttributeException if starting fails
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws AttributeException;
    
	/**
	 * Process attibutes and add them to <code>oAttributes</code>.
	 *
	 * @param sUserId the user where the attributes are gathered for
	 * @param oAttributes The attributes (in-out parameter).
	 * @throws AttributeException if gathering fails
	 */
	public void process(String sUserId, IAttributes oAttributes) 
        throws AttributeException;

    /**
     * Stops the processor.
     */
    public void stop();
    
}