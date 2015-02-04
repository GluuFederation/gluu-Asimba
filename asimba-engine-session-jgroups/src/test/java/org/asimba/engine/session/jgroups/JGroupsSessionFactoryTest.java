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
package org.asimba.engine.session.jgroups;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Scanner;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.cluster.JGroupsCluster;
import org.asimba.engine.session.jgroups.JGroupsSession;
import org.asimba.engine.session.jgroups.JGroupsSessionFactory;
import org.jgroups.JChannel;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.configuration.ConfigurationManager;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JGroupsSessionFactoryTest {
	private static final Log _oLogger = LogFactory.getLog(JGroupsSessionFactoryTest.class);

	private static final String FILENAME_CONFIG = "jgroupssessionfactory-config.xml";
	
	private static final String REQUESTOR_ID = "MYREQID";
	
	@Mock
	IUser mockedUser;
	
	@Mock
	SecureRandom mockedSecureRandom; 
	
	private static final long EXPIRATION_FOR_TEST = 500000;

	private static long nextBytesFillValue = 0;
	
	// nodenames in AvailableNodeNames must also be configured in FILENAME_CONFIG
	String[] AvailableNodeNames = {"one", "two", "three", "four", "five"};
	JGroupsSessionFactory[] Factories = new JGroupsSessionFactory[AvailableNodeNames.length];

	
	@Before
	public void before() {
		MockitoAnnotations.initMocks(this);
		nextBytesFillValue = 0l;
	
		mockedUser = Mockito.mock(IUser.class, withSettings().serializable());

		doAnswer(new Answer<Void>() {
			public Void answer(InvocationOnMock invocation) {
				byte[] bytes = (byte[]) invocation.getArguments()[0];
				setNextBytesAnswer(bytes, ++nextBytesFillValue);
				return null;
			}
		}).when(mockedSecureRandom).nextBytes(any(byte[].class));
		
		when(mockedUser.getID()).thenReturn("mockedUserID");
		when(mockedUser.getOrganization()).thenReturn("mockedUserOrganization");

		for (int i = 0; i < AvailableNodeNames.length; ++i) {
			Factories[i] = null;
		}
	}

	
	@After
	public void after() throws Exception {
		for (int i = 0; i < AvailableNodeNames.length; ++i) {
			if (Factories[i] != null) {
				cleanTheFactory(Factories[i]);
				Factories[i].stop();
				Factories[i] = null;
			}
		}		
	}
		

	public void setNextBytesAnswer(byte[] bytes, long value) {
	    byte[] id = BigInteger.valueOf(value).toByteArray();
		System.arraycopy(id, 0, bytes, 0, id.length);
	}
	
	
	/**
	 * Isolates problems related to serializability of JGroupsTGT
	 * @throws Exception
	 */
	@Test
	public void test01_JGroupsSessionSerializable() throws Exception {
		JGroupsSessionFactory oSessionFactory = createJGroupsSessionFactory(0, EXPIRATION_FOR_TEST);
		JGroupsSession oSession = (JGroupsSession) oSessionFactory.createSession(REQUESTOR_ID);
		
		try {
			SerializationUtils.serialize(oSession);
		}
		catch (Exception e) {
			_oLogger.error("Object of class JGroupsTGT cannot be serialized", e);
			assertThat("Serialization of JGroupsSession failed", true, equalTo(false)); // or the universe implodes
		}
	}

	
	@Test
	public void test02_OneNodeOneSession() throws Exception
	{
		testNSessionFactories(1, 1);
	}
	
	
	@Test
	public void test03_TwoNodeOneSession() throws Exception
	{
		testNSessionFactories(2, 1);
	}
	
	
	@Test
	public void test04_FiveNodeOneSession() throws Exception
	{
		testNSessionFactories(5, 1);
	}
	
	
	@Test
	public void test05_TwoNodeManySessions() throws Exception
	{
		testNSessionFactories(2, 500);
	}
	

	@Test
	public void test06_FiveNodeManySessions() throws Exception
	{
		testNSessionFactories(5, 500);
	}
	
	
	@Test
	public void test07_RunTwoNodesAndAddOne() throws Exception {
		final int nTGTs = 100;
		final int expectedTGTs = nTGTs * 2;
		testNSessionFactories(2, nTGTs);
		assertThat(Factories[0].size(), equalTo(expectedTGTs));
		assertThat(Factories[1].size(), equalTo(expectedTGTs));
		assertThat(Factories[2], equalTo(null));
		createFactory(2);
		JGroupsSessionFactory addedFactory = Factories[2];
		assertThat(addedFactory, not(equalTo(null)));
		assertThat(addedFactory.size(), equalTo(expectedTGTs));
		JGroupsSession newTGT = (JGroupsSession) addedFactory.createSession(REQUESTOR_ID);
		addedFactory.persist(newTGT);
		assertThat(addedFactory.size(), equalTo(expectedTGTs + 1));
		assertThat(Factories[0].size(), equalTo(expectedTGTs + 1));
		assertThat(Factories[1].size(), equalTo(expectedTGTs + 1));
	}
	
	


    /**
     * Test removal of expired TGTs
     */
    @Test
    public void test08_RemoveExpiredTGT() throws Exception {
        JGroupsSessionFactory sessionFactory = createJGroupsSessionFactory(0,1000);
        JGroupsSession session = (JGroupsSession) sessionFactory.createSession(REQUESTOR_ID);

        session.setUser(mockedUser);
        sessionFactory.persist(session);
        assertTrue(sessionFactory.exists(session.getId()));

		sessionFactory.removeExpired();

        Thread.sleep(1000);

        sessionFactory.removeExpired();
    }
	
	private void testNSessionFactories(int nNodes, int nSessions) throws Exception {
		int firstFreeNode = getFirstUnusedNode();
		if (firstFreeNode + nNodes > AvailableNodeNames.length) {
			_oLogger.error("Not enough unused nodes left");
			throw new Exception("Not enough unused nodes left");
		}
		
		for (int i = firstFreeNode; i < nNodes; ++i) {
			createFactory(i);
		}

		int persisted = 0;
		for (int i = 0; i < nNodes; ++i) {
			for (int j = 0; j < nSessions; ++j) {
				JGroupsSession session = (JGroupsSession) Factories[i].createSession(REQUESTOR_ID);
				Factories[i].persist(session);
				for (int k = 0; k < nNodes; ++k) {
					JGroupsSession rSession = Factories[i].retrieve(session.getId());
					assertThat("Assertion failed at: " + k, rSession, not(equalTo(null)));
					assertThat(rSession.getId(), equalTo(session.getId()));
				}
				++persisted;
			}
		}
		for (int i = 0; i < nNodes; ++i) {
			assertThat(Factories[i].size(), equalTo(persisted));
		}
	}

	
	private void createFactory(int i) throws Exception {
		Factories[i] = createJGroupsSessionFactory(i, EXPIRATION_FOR_TEST);
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
	

	private JGroupsSessionFactory createJGroupsSessionFactory(int n, long expiration) throws Exception {
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

		JGroupsSessionFactory oSessionFactory = Factories[n] = new JGroupsSessionFactory();
		oSessionFactory.startForTesting(oConfigManager, eClusterConfig, oCluster, mockedSecureRandom, 
				( expiration == 0 ) ? EXPIRATION_FOR_TEST : expiration );

		return oSessionFactory;
	}
	

	private void cleanTheFactory(JGroupsSessionFactory oSessionFactory) throws Exception {
/*		Set<Entry<String, JGroupsSession>> entries = oSessionFactory.entrySet();
		for (Entry<String, JGroupsSession> entry: entries) {
			oSessionFactory.clean(entry.getValue());
		}*/
	}
	


	private IConfigurationManager readConfigElementFromResource(String filename) throws Exception
	{
		
		InputStream oIS = JGroupsSessionFactory.class.getClassLoader().getResourceAsStream(filename);
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
