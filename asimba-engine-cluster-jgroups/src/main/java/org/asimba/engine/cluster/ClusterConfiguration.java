/*
 * Asimba Server
 * 
 * Copyright (C) 2015 Asimba
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
package org.asimba.engine.cluster;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.core.cluster.ICluster;
import org.asimba.engine.core.cluster.IClusterStorageFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.Engine;

public class ClusterConfiguration {

	private static final Log _oLogger = LogFactory.getLog(ClusterConfiguration.class);
	
	private IConfigurationManager _configManager;
	
	
	public ClusterConfiguration(IConfigurationManager configManager)
	{
		_configManager = configManager;
	}
	
	
	public ICluster getClusterFromConfigById(Element elConfig, String sConfigParam) throws ConfigurationException,
	OAException {
		String sClusterId = _configManager.getParam(elConfig, sConfigParam);

		if (sClusterId == null) {
			_oLogger.fatal("Required Element '"+sConfigParam+"' is not configured.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}

		IClusterStorageFactory oClusterStorageFactory = Engine.getInstance().getClusterStorageFactory();
		if (oClusterStorageFactory == null) {
			_oLogger.fatal("The required ClusterStorageFactory is NOT configured!");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}

		ICluster oCluster = oClusterStorageFactory.getCluster(sClusterId);
		if (oCluster == null) {
			_oLogger.fatal("Configured cluster '"+sClusterId+"' is not available.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}

		return oCluster;
	}
}
