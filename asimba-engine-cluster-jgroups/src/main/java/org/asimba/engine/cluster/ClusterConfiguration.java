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
