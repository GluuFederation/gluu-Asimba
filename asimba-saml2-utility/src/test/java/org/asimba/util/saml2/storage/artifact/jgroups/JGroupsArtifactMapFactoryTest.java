package org.asimba.util.saml2.storage.artifact.jgroups;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

import java.io.InputStream;
import java.io.Serializable;
import java.util.Properties;
import java.util.Scanner;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.cluster.JGroupsCluster;
import org.jgroups.JChannel;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectHelper;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.saml1.core.impl.NameIdentifierBuilder;
import org.opensaml.xml.ConfigurationException;
import org.w3c.dom.Element;

import static org.junit.Assert.assertEquals;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.configuration.ConfigurationManager;
import com.alfaariss.oa.util.saml2.storage.artifact.ArtifactMapEntry;

public class JGroupsArtifactMapFactoryTest {

	private static final Log _oLogger = LogFactory.getLog(JGroupsArtifactMapFactoryTest.class);
	
	private static final String FILENAME_CONFIG = "jgroupsfactory-config-ok.xml";

	String[] AvailableNodeNames = {"one", "two", "three", "four", "five"};
	JGroupsArtifactMapFactory[] Factories = new JGroupsArtifactMapFactory[AvailableNodeNames.length];

	
	@Before
	public void before() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test
	public void test01_JGroupsSessionSerializable() throws Exception {
		ArtifactMapEntry ae = new ArtifactMapEntry();
		byte[] aes = null;
		ArtifactMapEntry aed = null;
		
		try {
			aes = SerializationUtils.serialize(ae);
		}
		catch (Exception e) {
			_oLogger.error("Object of class ArtifactMapEntry cannot be serialized", e);
			throw e;
			//assertThat("Serialization of ArtifactMapEntry failed", true, equalTo(false)); // or the universe implodes
		}
		
		//aed = SerializationUtils.deserialize(aes);
		//System.out.println(aes.toString() + " + " + aed);
		//assertEquals(ae, aed);
	}


	@Test
	public void test02_OneNodeOneEntry() throws Exception {
		testNArtifactMapFactories(1, 1);
	}
	
	
	//@Test
	public void test03_TwoNodeManyEntries() throws Exception {
		testNArtifactMapFactories(2, 100);
	}
	
	
	private void testNArtifactMapFactories(int nNodes, int nEntries) throws Exception {
		int firstFreeNode = getFirstUnusedNode();
		if (firstFreeNode + nNodes > AvailableNodeNames.length) {
			_oLogger.error("Not enough unused nodes left");
			throw new Exception("Not enough unused nodes left");
		}
		
		for (int i = firstFreeNode; i < nNodes; ++i) {
			createJGroupsArtifactMapFactory(i);
		}

		int persisted = 0;
		for (int i = 0; i < nNodes; ++i) {
			for (int j = 0; j < nEntries; ++j) {
				String id = (new Integer(j)).toString();
				Factories[i].put(id, id, id, new NameIdentifierBuilder().buildObject());
				for (int k = 0; k < nNodes; ++k) {
					SAMLArtifactMapEntry rSAMLObject = Factories[i].get(id);
					assertThat("Assertion failed at: " + k, rSAMLObject, not(equalTo(null)));
					assertThat(rSAMLObject.getArtifact(), equalTo(id));
				}
				++persisted;
			}
		}
		for (int i = 0; i < nNodes; ++i) {
			assertThat(Factories[i].size(), equalTo(persisted));
		}		
	}
	
	
	private int getFirstUnusedNode() throws Exception {
		for (int i = 0; i < AvailableNodeNames.length; ++i) {
			if (Factories[i] == null) {
				return i;
			}
		}
		
		String message = "No unused nodes left";
		_oLogger.error(message);
		throw new Exception(message);
	}
	

	private JGroupsArtifactMapFactory createJGroupsArtifactMapFactory(int n) throws Exception
	{
		String id = AvailableNodeNames[n];
		System.setProperty(JGroupsCluster.PROP_ASIMBA_NODE_ID, id);

		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG);

		Element eClusterConfig = oConfigManager.getSection(
				null, "cluster", "id=test");            
		assertThat(eClusterConfig, not(equalTo(null)));

		JGroupsCluster oCluster = new JGroupsCluster();
		oCluster.start(oConfigManager, eClusterConfig);
		JChannel jChannel = (JChannel) oCluster.getChannel();
		assertThat(jChannel, not(equalTo(null)));
		_oLogger.info("JCluster address:" + jChannel.getAddressAsString());

		JGroupsArtifactMapFactory oSessionFactory = Factories[n] = new JGroupsArtifactMapFactory();
		oSessionFactory.startForTesting(oConfigManager, oCluster);

		return oSessionFactory;
}
	
	
	private IConfigurationManager readConfigElementFromResource(String filename) throws Exception
	{
		
		InputStream oIS = JGroupsArtifactMapFactoryTest.class.getClassLoader().getResourceAsStream(filename);
		String sConfig;
		
		try (Scanner s = new Scanner(oIS, "UTF-8")) {
			s.useDelimiter("\\A");
			sConfig = s.next();
		}
		
		//_oLogger.info("XML Read: [" + sConfig + "]");
		
		Properties oProperties = new Properties();
		oProperties.put("configuration.handler.class", 
				"com.alfaariss.oa.util.configuration.handler.text.PlainTextConfigurationHandler");
		oProperties.put("config", sConfig);
		
		ConfigurationManager oConfigManager = ConfigurationManager.getInstance();
		oConfigManager.start(oProperties);
		
		return oConfigManager;
	}
}
