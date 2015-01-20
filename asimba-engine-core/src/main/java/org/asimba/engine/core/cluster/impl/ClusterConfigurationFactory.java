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
package org.asimba.engine.core.cluster.impl;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.core.cluster.ICluster;
import org.asimba.engine.core.cluster.IClusterStorageFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

public class ClusterConfigurationFactory implements IClusterStorageFactory, IComponent
{

	/** Configuration elements */
	public static final String EL_CLUSTER = "cluster";

	/** Local logger instance */
	private static Log _oLogger = LogFactory.getLog(ClusterConfigurationFactory.class);

	/** Local reference to configmanager for reloading configuration */
	private IConfigurationManager _oConfigManager;

	/** Map of configured clusters */
	private Map<String, ICluster> _mClusters;


	@Override
	public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException 
	{
		_oConfigManager = oConfigurationManager;

		_oLogger.info("Starting Cluster configuration");
		_mClusters = new HashMap<>();

		Element elCluster = _oConfigManager.getSection(eConfig, EL_CLUSTER);
		if (elCluster == null) {
			_oLogger.warn("No '"+EL_CLUSTER+"' item found, no clusters available!");
		} else {
			while (elCluster != null) {
				ICluster oCluster = createCluster(_oConfigManager, elCluster);
				_mClusters.put(oCluster.getID(), oCluster); 
				_oLogger.info("Established cluster '"+oCluster.getID()+"'");

				elCluster = _oConfigManager.getNextSection(elCluster);
			}
		}

		_oLogger.info("Started Cluster configuration");

	}

	
	@Override
	public void restart(Element eConfig) throws OAException {
		stop();
		start(_oConfigManager, eConfig);
	}

	
	@Override
	public void stop() {
		for (ICluster oCluster: _mClusters.values()) {
			((IComponent)oCluster).stop();
		}
		
		_mClusters.clear();
		_oLogger.info("Stopped Cluster configuration");
	}

	
	@Override
	public ICluster getCluster(String sClusterName)  {
		return _mClusters.get(sClusterName);
	}


	private ICluster createCluster(IConfigurationManager oConfigManager, Element elCluster) throws OAException
	{
		String sClass = oConfigManager.getParam(elCluster, "class");
		if (sClass == null) {
			_oLogger.error("No 'class' item found in '"+EL_CLUSTER+"' section");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}

		Class<?> oClass = null;
		try {
			oClass = Class.forName(sClass);
		}
		catch (Exception e) {
			_oLogger.error("No 'class' found with name: " + sClass, e);
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}

		ICluster oCluster = null;
		try {
			oCluster = (ICluster) oClass.newInstance();
		}
		catch (Exception e) {
			_oLogger.error("Could not create 'ICluster' instance of the 'class' with name: " 
					+ sClass, e);
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}

		// Start the Cluster handler
		((IComponent)oCluster).start(oConfigManager, elCluster);

		// And deliver
		return oCluster;
	}

}
