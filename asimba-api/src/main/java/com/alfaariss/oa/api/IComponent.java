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
package com.alfaariss.oa.api;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * The component interface for OA components.
 * 
 * The component interface that makes the OA components startable, restartable 
 * and stoppable by the engine. Components are required to throw exceptions when
 * called and not yet initialized.
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IComponent 
{
	/**
	 * Start the component.
	 * @param oConfigurationManager the configuration manager used to retrieve 
     * the config from the supplied <code>Element</code>. 
	 * @param eConfig The configuration section or <code>null</code> if no 
     * configuration is found.
	 * @throws OAException 
	 */
	public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws OAException;

	/**
	 * Restart the component with the supplied configuration.
	 *
	 * @param eConfig The configuration section, 
     *  or <code>null</code> if no configuration is found.
	 * @throws OAException 
	 */
	public void restart(Element eConfig) throws OAException;

	/**
	 * Stops the component.
	 */
	public void stop();

}