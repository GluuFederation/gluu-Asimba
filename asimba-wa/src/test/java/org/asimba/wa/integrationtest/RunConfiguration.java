package org.asimba.wa.integrationtest;

import java.io.IOException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Singleton that is responsible for loading config properties
 *  
 * @author mdobrinic
 *
 */
public class RunConfiguration {
	private static Logger _logger = LoggerFactory.getLogger(RunConfiguration.class);

	private Properties _properties = null;
	
	private static RunConfiguration _runConfiguration = null;
	
	public static RunConfiguration getInstance()
	{
		if (_runConfiguration == null) _runConfiguration = new RunConfiguration();
		return _runConfiguration;
	}
	
	private RunConfiguration() 
	{
		_properties = new Properties();
		try {
			_properties.load(this.getClass().getClassLoader().getResourceAsStream("runconfiguration.properties"));
		} catch (IOException e) {
			_logger.error("Could not load properties.");
			return;
		}
		
	}
	
	public String getProperty(String key, String defaultValue)
	{
		if (_properties == null) return defaultValue;
		return _properties.getProperty(key, defaultValue);
	}
	
	public String getProperty(String key)
	{
		return getProperty(key, null);
	}
	
	public Properties getProperties()
	{
		return (Properties) _properties.clone();
	}
}
