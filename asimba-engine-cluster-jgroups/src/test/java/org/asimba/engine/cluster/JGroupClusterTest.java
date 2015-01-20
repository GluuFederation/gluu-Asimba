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

public class JGroupClusterTest {
	private static final Log _oLogger = LogFactory.getLog(JGroupClusterTest.class);
	
	private static final String FILENAME_CONFIG_OK = "jgroupcluster-config-ok.xml";
	
	@Test
	public void testSetupOk() throws Exception
	{
		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG_OK);

		Element eClusterElement = oConfigManager.getSection(
                null, "cluster");            
		
		assertThat(eClusterElement, not(equalTo(null)));
		
		JGroupCluster oJGroupCluster = new JGroupCluster();
		oJGroupCluster.start(oConfigManager, eClusterElement);
		
		assertThat(oJGroupCluster.getID(), equalTo("test"));
		
		// node="one", of node="two"
		System.setProperty(JGroupCluster.PROP_ASIMBA_NODE_ID, "one");
		
		JChannel jChannel = (JChannel) oJGroupCluster.getChannel();
		assertThat(jChannel, not(equalTo(null)));
		assertThat(jChannel.getClusterName(), equalTo("test-cluster"));
		
		assertThat(jChannel.getState(), equalTo("CONNECTED"));
	}

	
	private IConfigurationManager readConfigElementFromResource(String filename) throws Exception
	{
		
		InputStream oIS = JGroupClusterTest.class.getClassLoader().getResourceAsStream(filename);
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
