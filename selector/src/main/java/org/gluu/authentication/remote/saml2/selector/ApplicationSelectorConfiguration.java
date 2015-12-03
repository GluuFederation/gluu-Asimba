package org.gluu.authentication.remote.saml2.selector;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Configuration for application based selector
 * 
 * @author Yuriy Movchan Date: 16/05/2014
 */
public class ApplicationSelectorConfiguration {

	private Log log;

	private final String CONFIGURATION_FILE_NAME = "asimba-selector.xml";

	private Map<String, String> applicationMapping;

	private final ReentrantLock reloadLock = new ReentrantLock();
	private boolean isReload = false;

	private long lastModTime = -1;

	public ApplicationSelectorConfiguration() {
		this.log = LogFactory.getLog(ApplicationSelectorConfiguration.class);
		this.applicationMapping = new HashMap<String, String>();
	}

	public void loadConfiguration() {
		this.applicationMapping = new HashMap<String, String>();

		String confFilePath = getConfigurationFilePath();
		if (confFilePath == null) {
			return;
		}

		File confFile = new File(confFilePath);
		if (this.lastModTime == confFile.lastModified()) {
			return;
		}
	
		loadFileSync(confFile);
	}

	public String getConfigurationFilePath() {
		String tomcatHome = System.getProperty("catalina.home");
		if (tomcatHome == null) {
			log.error("Failed to load mapping from '" + CONFIGURATION_FILE_NAME + "'. The environment variable catalina.home isn't defined");
			return null;
		}
		
		String confPath = System.getProperty("catalina.home") + File.separator + "conf" + File.separator + CONFIGURATION_FILE_NAME;
		log.info("Reading configuration from: " + confPath);
		
		return confPath;
	}

	private void loadFileSync(File confFile) {
		this.isReload = true;

		reloadLock.lock(); // block until condition holds
		try {
			if (!this.isReload) {
				return;
			}

			loadFile(confFile);
		} finally {
            reloadLock.unlock();
            this.isReload = false;
		}
	}

	private void loadFile(File confFile) {
		try {
			DocumentBuilderFactory fty = DocumentBuilderFactory.newInstance();
			fty.setNamespaceAware(true);
			DocumentBuilder builder = fty.newDocumentBuilder();
			Document xmlDoc = builder.parse(confFile);

			// Load mapping
			this.applicationMapping = loadIdpMapping(xmlDoc);
			this.lastModTime = confFile.lastModified();
		} catch (Exception ex) {
			log.error("Faield to load mapping configuration", ex);
		}
	}

	private Map<String, String> loadIdpMapping(Document xmlDoc) throws XPathExpressionException {
		Map<String, String> result = new HashMap<String, String>();
		XPath xPath = XPathFactory.newInstance().newXPath();

		XPathExpression query = xPath.compile("/asimba-selector/application");
		NodeList nodes = (NodeList) query.evaluate(xmlDoc, XPathConstants.NODESET);
		for (int i = 0; i < nodes.getLength(); i++) {
			Node node = nodes.item(i);

			Node entityIdNode = node.getAttributes().getNamedItem("entityId");
			if (entityIdNode == null) {
				continue;
			}

			Node organizationIdNode = node.getAttributes().getNamedItem("organizationId");
			if (organizationIdNode == null) {
				continue;
			}
			
			result.put(entityIdNode.getNodeValue(), organizationIdNode.getNodeValue());
		}

		return result;
	}

	public Map<String, String> getApplicationMapping() {
		return applicationMapping;
	}

}

