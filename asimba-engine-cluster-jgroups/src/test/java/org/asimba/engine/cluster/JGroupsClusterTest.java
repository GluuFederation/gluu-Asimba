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

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

import java.io.InputStream;
import java.util.Properties;
import java.util.Scanner;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jgroups.JChannel;
import org.junit.Test;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.configuration.ConfigurationManager;
import javax.naming.Context;
import static org.asimba.engine.cluster.JGroupsCluster.PROP_ASIMBA_NODE_ID;
import org.junit.Rule;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;


public class JGroupsClusterTest {
	private static final Log _oLogger = LogFactory.getLog(JGroupsClusterTest.class);
	
	private static final String FILENAME_CONFIG_OK = "jgroupscluster-config-ok.xml";
	
    private final Context context = mock(Context.class);

    @Rule
    public MockInitialContextRule mockInitialContextRule = new MockInitialContextRule(context);
    
	@Test
	public void testSetupOk() throws Exception
	{
		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG_OK);

		Element eClusterElement = oConfigManager.getSection(
                null, "cluster");            
		
		assertThat(eClusterElement, not(equalTo(null)));
		
		JGroupsCluster oJGroupsCluster = new JGroupsCluster();
        assertThat(oJGroupsCluster, not(equalTo(null)));
        
		oJGroupsCluster.start(oConfigManager, eClusterElement);
		
		assertThat(oJGroupsCluster.getID(), equalTo("test"));
		
		// node="one", of node="two"
		System.setProperty(JGroupsCluster.PROP_ASIMBA_NODE_ID, "one");
		
		JChannel jChannel = (JChannel) oJGroupsCluster.getChannel();
		assertThat(jChannel, not(equalTo(null)));
		assertThat(jChannel.getClusterName(), equalTo("test-cluster"));
		
		assertThat(jChannel.getState(), equalTo("CONNECTED"));
	}

    
    @Test
    public void testNodeNameFromHostName() throws Exception {
        final String NODE_FROM_CONFIG = "one";
		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG_OK);

		Element eClusterElement = oConfigManager.getSection(
                null, "cluster");            
		
		assertThat(eClusterElement, not(equalTo(null)));

        // a unit test with actual host names is not possible, as a unit test needs to be independent
        // from its environment. Therefore, mock the hostname. So this test does not actually
        // test getting a hostname from the system, it just confirms that the node id is actually
        // based on a call to InetAddress.getLocalHost().getHostName()
		JGroupsCluster oJGroupsCluster = spy(new JGroupsCluster());
		oJGroupsCluster.start(oConfigManager, eClusterElement);
		
		assertThat(oJGroupsCluster.getID(), equalTo("test"));
		
        doReturn(NODE_FROM_CONFIG).when(oJGroupsCluster).getHostName(); //matches node id in config
        assertThat(oJGroupsCluster, not(equalTo(null)));
        JChannel channel = (JChannel) oJGroupsCluster.getChannel();

        // the channel is configured using a node id in the config, so if there is a channel, we're good
        assertThat(channel, not(equalTo(null)));
    }
    
    
    @Test 
    public void testNodeNameFromSystemProperty() throws Exception {        
        final String NODE_FROM_CONFIG = "two";
        final String INVALID_HOSTNAME = "invalid hostname";
		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG_OK);

		Element eClusterElement = oConfigManager.getSection(
                null, "cluster");            
		
		assertThat(eClusterElement, not(equalTo(null)));

		JGroupsCluster oJGroupsCluster = spy(new JGroupsCluster());
		oJGroupsCluster.start(oConfigManager, eClusterElement);
        assertThat(oJGroupsCluster.getID(), equalTo("test"));
		
        System.setProperty(JGroupsCluster.PROP_ASIMBA_NODE_ID, NODE_FROM_CONFIG);
        
        // fake a hostname so that test will fail if the system property wasn't used
        doReturn(INVALID_HOSTNAME).when(oJGroupsCluster).getHostName(); //matches node id in config
        assertThat(oJGroupsCluster, not(equalTo(null)));
        JChannel channel = (JChannel) oJGroupsCluster.getChannel();

        // the channel is configured using a node id in the config, so if there is a channel, we're good
        assertThat(channel, not(equalTo(null)));
    }
    
	
    @Test 
    public void testNodeNameFromInitialContext() throws Exception {
        final String NODE_FROM_CONFIG = "one";
        final String INVALID_SYSTEM_PROPERTY = "invalid system property";
        final String INVALID_HOSTNAME = "invalid hostname";

        when(context.lookup("java:comp/env/"+PROP_ASIMBA_NODE_ID)).thenReturn(NODE_FROM_CONFIG);

		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG_OK);

		Element eClusterElement = oConfigManager.getSection(
                null, "cluster");            
		
		assertThat(eClusterElement, not(equalTo(null)));

		JGroupsCluster oJGroupsCluster = spy(new JGroupsCluster());
		oJGroupsCluster.start(oConfigManager, eClusterElement);
        assertThat(oJGroupsCluster.getID(), equalTo("test"));
		
        // fake a system property so the test will fail if the initial context wasn't used
        System.setProperty(JGroupsCluster.PROP_ASIMBA_NODE_ID, INVALID_SYSTEM_PROPERTY);
        
        // fake a hostname so the test will fail if the system property wasn't used
        doReturn(INVALID_HOSTNAME).when(oJGroupsCluster).getHostName(); //matches node id in config
        assertThat(oJGroupsCluster, not(equalTo(null)));
        JChannel channel = (JChannel) oJGroupsCluster.getChannel();

        // the channel is configured using a node id in the config, so if there is a channel, we're good
        assertThat(channel, not(equalTo(null)));
    }
    
    
	
	private IConfigurationManager readConfigElementFromResource(String filename) throws Exception
	{
		
		InputStream oIS = JGroupsClusterTest.class.getClassLoader().getResourceAsStream(filename);
		String sConfig;
		
		try (Scanner s = new Scanner(oIS, "UTF-8")) {
			s.useDelimiter("\\A");
			sConfig = s.next();
		}
		
		_oLogger.info("XML Read: [" + sConfig + "]");
		
		Properties oProperties = new Properties();
		oProperties.put("configuration.handler.class", 
				"com.alfaariss.oa.util.configuration.handler.text.PlainTextConfigurationHandler");
		oProperties.put("config", sConfig);
		
		ConfigurationManager oConfigManager = ConfigurationManager.getInstance();
		oConfigManager.start(oProperties);
		
		return oConfigManager;
	}
}
