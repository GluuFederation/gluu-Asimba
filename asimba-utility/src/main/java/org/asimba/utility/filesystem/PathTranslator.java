/**
 * 
 * PathTranslator
 * 
 * Translate a path by interpreting relative mounting points
 * 
 * Accepts manual translation entries, but provides the following
 * mapping entries that are always available:
 * - ${user.dir} translates to the home directory of the current user
 * 
 * Example: This can be used in configuration, like this:
 * <file>$application.webinf/userfile/users.xml</file>
 * to point to the userfile/users.xml in the WEB-INF dir of the webapp  
 * 
 * (c) Asimba SSO
 * 
 */
package org.asimba.utility.filesystem;

import java.util.HashMap;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

public class PathTranslator {
	private static String Version = "1.0/201203";
	
	/**
	 * Logger instance
	 */
	private Logger _oLogger = Logger.getLogger(PathTranslator.class);
	

	/**
	 * PathTranslator instance, managed by singleton construct
	 */
	protected static PathTranslator _oPathTranslator = null;

	/**
	 * Access to singleton PathTransator instance
	 * @return PathTranslator instance to work with
	 */
	public static PathTranslator getInstance() {
		if (_oPathTranslator==null) {
			_oPathTranslator = new PathTranslator();
		}
		return _oPathTranslator;
	}
	
	
	/**
	 * Store reference of ConfigManager in local context
	 */
	protected IConfigurationManager _oConfigManager;

	/**
	 * _hmDictionary contains the keys and their translation
	 * i.e. '$user.home' translates to the current user's home directory
	 */
	protected HashMap<String, String> _hmDictionary;
	

	/**
	 * Private constructor for static singleton instance of PathTranslator
	 */
	private PathTranslator() {
		_hmDictionary = new HashMap<String, String>();

		// Always make ${user.dir} available (if there is any)
		String sUserdir = System.getProperty("user.dir");
		if (sUserdir != null) {
			addKey("user.dir", sUserdir);
		}
	}
	
	
	/**
	 * Append user configurable mountpoints to the dictionary
	 * Entries are listed as &lt;mountpoint key="[key]"&gt;[value]&lt;/mountpoint&gt;
	 */
	public void start(IConfigurationManager _oConfigManager,
			Element eConfig) throws OAException 
	{
		_oLogger.info("Started PathTranslator ("+Version+")");
	}


	public synchronized void restart(Element eConfig) throws OAException {
		stop();
		start(_oConfigManager, eConfig);
	}


	public void stop() {
		_oLogger.info("Stopping PathTranslator ("+Version+")");
	}
	

	/**
	 * Add new mounting-point to mapping table
	 * @param sKey Key to add
	 * @param sValue Location of the mounting-point for the key
	 */
	public void addKey(String sKey, String sValue) {
		_hmDictionary.put(sKey, sValue);
	}

	
	/**
	 * Remove a mapping key from the mapping table
	 * @param sKey Key to remove
	 */
	public void removeKey(String sKey) {
		_hmDictionary.remove(sKey);
	}
	

	/**
	 * Filter a filename to expand the mounting-points in a filename with
	 *    absolute locations; a filename could be "${webapp.root}/WEB-INF"
	 * @param sFilename Filename to expand
	 * @return String with optional mounting-points replaced
	 */
	public String map(String sFilename) {
		String re;
		String r = sFilename;
		
		for(String k: _hmDictionary.keySet()) {
			re = "${"+k+"}";
			if (r.contains(re)) {	// Replace when found
				// Prepare input to be valid RegEx input strings
				String s= "\\"+re.replace("{","\\{").replace("}","\\}");
				// windows backslash as path-separator fix
				String t=_hmDictionary.get(k).replaceAll("\\\\", "\\\\\\\\");	
				r = sFilename.replaceAll(s, t);
			}
		}
		
		return r;
	}
	
}
