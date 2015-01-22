package org.asimba.engine.cluster;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.core.cluster.ICluster;
import org.jgroups.JChannel;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;


/**
 * Configurable through:<br/>
 * <br/>
 * &lt;cluster class="org.asimba.engine.cluster.JGroupCluster" @id&gt;<br/>
 *   &lt;config_location&gt; ... &lt;config_location&gt;<br/>
 *   &lt;cluster_name&gt; ... &lt;cluster_name&gt;<br/>
 *   &lt;node @id&gt;<br/>
 *     &lt;options&gt;<br/>
 *       &lt;option @name @value /&gt;<br/>
 *       ...<br/>
 *       &lt;option @name @value /&gt;<br/>
 *     &lt;/options&gt;<br/>
 *   &lt;/node<br/>
 * &lt;/cluster&gt;<br/>
 * 
 * @author mdobrinic
 *
 */
public class JGroupCluster implements ICluster, IComponent {

	/** Configuration elements */
	public static final String ATTR_ID = "id";
	public static final String EL_CONFIG_LOCATION = "config_location";
	public static final String EL_CLUSTER_NAME = "cluster_name";
	public static final String EL_NODE = "node";
	public static final String EL_OPTIONS = "options";
	public static final String EL_OPTION = "option";
	public static final String ATTR_NAME = "name";
	public static final String ATTR_VALUE = "value";
	public static final String[] ALLOWED_OPTIONS = {"jgroups.bind_addr", "jgroups.tcp.bind_port", "jgroups.tcpping.initial_hosts"};

	/** System Properties */
	public static final String PROP_ASIMBA_NODE_ID = "asimba.node.id";

	/** Local logger instance */
	private static Log _oLogger = LogFactory.getLog(JGroupCluster.class);

	/** Local reference to configmanager for reloading configuration */
	private IConfigurationManager _oConfigManager;

	/** Configurable ID of the cluster */
	protected String _sID;

	/** The location of the JGroup Channel configuration; <br/> 
	 * see: http://jgroups.org/manual/index.html#CreatingAChannel
	 * */
	private String _sConfigLocation;

	/** Name of the cluster (aka group) */
	private String _sClusterName;
	
	/** The JGroup JChannel */
	private JChannel _jChannel;

	/** 
	 * Custom configured options that are filtered based on startup option;
	 * The map is built as:<br/>
	 * [ node.id -> [ option.key -> option.value, ... ] , node.id -> [ ... ] <br/>
	 * that is used based on the system property PROP_ASIMBA_NODE_ID<br/>
	 * 
	 */  
	private Map<String, Map <String, String>> _mCustomOptions;


	@Override
	public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException 
	{
		_oLogger.info("Starting JGroupCluster");
		_oConfigManager = oConfigurationManager;

		_jChannel = null;
		
		_sID = _oConfigManager.getParam(eConfig, ATTR_ID);
		if (_sID == null) {
			_oLogger.error("No 'id' configured for cluster");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}

		_sConfigLocation = _oConfigManager.getParam(eConfig, EL_CONFIG_LOCATION);
		if (_sConfigLocation == null) {
			_oLogger.info("Cluster '"+_sID+"' has no '"+EL_CONFIG_LOCATION+"' configured; using default.");
		} else {
			_oLogger.info("Cluster '"+_sID+"' uses configuration from '"+_sConfigLocation+"'");
		}

		_sClusterName = _oConfigManager.getParam(eConfig, EL_CLUSTER_NAME);
		if (_sClusterName == null) {
			_oLogger.error("Cluster '"+_sID+"' has no '"+EL_CLUSTER_NAME+"' configured; using default.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		_mCustomOptions = new HashMap<>();

		Element elNode = null;
		String sNodeId = null;

		elNode = _oConfigManager.getSection(eConfig, EL_NODE);
		while (elNode != null) {
			sNodeId = _oConfigManager.getParam(elNode, ATTR_ID);
			if (sNodeId == null) {
				_oLogger.error("No 'id' configured for node");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}

			Element elOptions = _oConfigManager.getSection(elNode, EL_OPTIONS);
			if (elOptions != null) {
				Map<String, String> oNodeOptions = loadCustomOptions(_oConfigManager, elOptions);
				_mCustomOptions.put(sNodeId, oNodeOptions);
			}

			_oLogger.info("Initialized custom options for node "+_sID);
			
			elNode = _oConfigManager.getNextSection(elNode);
		}

		_oLogger.info("JGroupCluster '"+_sID+"' started");
	}

	@Override
	public void restart(Element eConfig) throws OAException {
		stop();
		start(_oConfigManager, eConfig);
	}

	@Override
	public void stop() {
		_oLogger.info("JGroupCluster "+_sID+" stopped.");
	}

	@Override
	public String getID() {
		return _sID;
	}


	/**
	 * Load options
	 * @param elOptions
	 * @throws ConfigurationException 
	 */
	private Map<String, String> loadCustomOptions(IConfigurationManager oConfigManager, 
			Element elOptions) throws ConfigurationException {
		Map<String, String> mOptions = new HashMap<>();

		Element elOption = oConfigManager.getSection(elOptions, EL_OPTION);
		while (elOption != null) {
			String sName = oConfigManager.getParam(elOption, ATTR_NAME);
			String sValue = oConfigManager.getParam(elOption, ATTR_VALUE);
			if (Arrays.asList(ALLOWED_OPTIONS).contains(sName)) {
				mOptions.put(sName, sValue);
			} else {
				_oLogger.warn("Invalid option configured: '"+sName+"'; ignoring");
			}
			
			elOption = oConfigManager.getNextSection(elOption);
		}
		
		return mOptions;
	}

	/**
	 * Return the JChannel instance configured for this JGroupCluster<br/>
	 * Note: the JChannel is connected to upon first instantiation
	 */
	@Override
	public Object getChannel() {
		if (_jChannel == null) {
			// Initialize the channel, based on configuration
			String sNodeId = System.getProperty(PROP_ASIMBA_NODE_ID);
			// sNodeId == null when property not set

			try {
				if (sNodeId != null) {
					// Apply custom options:
					Map<String, String> mOptions = _mCustomOptions.get(sNodeId);
					
					_oLogger.info("System property "+PROP_ASIMBA_NODE_ID+" specified; applying"
							+ "custom properties JGroupCluster '"+_sID+"', node '" + sNodeId + "'");

					for (Entry<String, String> prop: mOptions.entrySet()) {
						System.setProperty(prop.getKey(), prop.getValue());
					}
							
				} else {
					_oLogger.info("No "+PROP_ASIMBA_NODE_ID+" system property specified, so no "
							+ "custom properties applied for JGroupCluster '"+_sID+"'");
				}

				_jChannel = new JChannel(_sConfigLocation);
				if (_sID != null) _jChannel.setName(_sID);
				
				_oLogger.info("Connecting to cluster "+_sID+" with name "+_sClusterName);
				_jChannel.connect(_sClusterName);
				
			} catch (Exception e) {
				_oLogger.error("Could not create JChannel: "+e.getMessage(), e);
				return null;
			}
		}

		return _jChannel;
	}

	@Override
	public void close()
	{
		if (_jChannel != null) {
			_jChannel.close();

			_jChannel = null;
		}
	}

}
