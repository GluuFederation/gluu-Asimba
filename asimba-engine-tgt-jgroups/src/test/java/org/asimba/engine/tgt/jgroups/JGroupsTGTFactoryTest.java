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
package org.asimba.engine.tgt.jgroups;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Scanner;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.cluster.JGroupCluster;
import org.jgroups.JChannel;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.Mockito.*;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.configuration.ConfigurationManager;

public class JGroupsTGTFactoryTest {
	private static final Log _oLogger = LogFactory.getLog(JGroupsTGTFactoryTest.class);

	private static final String FILENAME_CONFIG_OK = "jgroupsfactory-config-ok.xml";
	

	@Mock
	SecureRandom mockedSecureRandom; 

	@Before
	public void before() {
		MockitoAnnotations.initMocks(this);

		doAnswer(new Answer<Void>() {
			public Void answer(InvocationOnMock invocation) {
				byte[] bytes = (byte[]) invocation.getArguments()[0];
				java.util.Arrays.fill(bytes, (byte)1);
				return null;
			}
		}).when(mockedSecureRandom).nextBytes(any(byte[].class));		
	}
	
	@Test
	public void testOneTGTFactory() throws Exception {
		JGroupsTGTFactory oTGTFactory = createJGroupsTGTFactory("two");

		JGroupsTGT oTGT = (JGroupsTGT) oTGTFactory.createTGT(null);
		assertThat(oTGT, not(equalTo(null)));
		assertThat(oTGT.getId(), equalTo(null));
		oTGTFactory.persist(oTGT);
		assertThat(oTGT.getId(), not(equalTo(null)));
	}
	
	private JGroupsTGTFactory createJGroupsTGTFactory(String id) throws Exception
	{
		System.setProperty(JGroupCluster.PROP_ASIMBA_NODE_ID, id);
		
		JGroupsTGTFactory oTGTFactory = new JGroupsTGTFactory();

		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG_OK);

		Element eClusterElement = oConfigManager.getSection(
                null, "cluster", "id=test");            
		assertThat(eClusterElement, not(equalTo(null)));
		
		Element eAliasClusterElement = oConfigManager.getSection(
                null, "alias-cluster", "id=test-alias");            
		assertThat(eAliasClusterElement, not(equalTo(null)));
		
		JGroupCluster oCluster = new JGroupCluster();
		oCluster.start(oConfigManager, eClusterElement);
		JChannel jChannel = (JChannel) oCluster.getChannel();
		assertThat(jChannel, not(equalTo(null)));
		//assertThat(jChannel.getAddressAsString().endsWith("7800"), equalTo(true));
		_oLogger.info("JCluster address:" + jChannel.getAddressAsString());
		JGroupCluster oAliasCluster = new JGroupCluster();
		oAliasCluster.start(oConfigManager, eAliasClusterElement);
		
		oTGTFactory.setSecureRandom(mockedSecureRandom);
		oTGTFactory.start(oConfigManager, eClusterElement, oCluster, oAliasCluster);

		return oTGTFactory;
	}

	private IConfigurationManager readConfigElementFromResource(String filename) throws Exception
	{
		
		InputStream oIS = JGroupsTGTFactory.class.getClassLoader().getResourceAsStream(filename);
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
