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

import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jgroups.JChannel;
import org.jgroups.blocks.ReplicatedHashMap;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.*;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.user.IUser;

import org.asimba.engine.cluster.JGroupsCluster;

import com.alfaariss.oa.engine.core.configuration.ConfigurationManager;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;


@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JGroupsTGTFactoryTest {
	private static final Log _oLogger = LogFactory.getLog(JGroupsTGTFactoryTest.class);

	private static final String FILENAME_CONFIG = "jgroupsfactory-config-ok.xml";
	
	private static final long EXPIRATION_FOR_TEST = 500000;
    private static final boolean USE_BLOCKING_UPDATES = true;
    private static final long BLOCKING_TIMEOUT = 5000;
	
	// current implementation of setNextFillBytes supports up to 255 unique values :(
	private static final long MAX_FILLBYTES_VALUE = 255;
	private static long nextBytesFillValue = 0;
	
	private static final String IDP_TYPE = "IDP";
	private static final String SP_TYPE = "SP";
	private static final String SOME_REQUESTOR = "someRequestor";
	private static final String SOME_ALIAS = "someAlias";

	@Mock
	SecureRandom mockedSecureRandom; 

	@Mock
	IUser mockedUser;
	
	// nodenames in AvailableNodeNames must also be configured in FILENAME_CONFIG
	String[] AvailableNodeNames = {"one", "two", "three", "four", "five"};
	JGroupsTGTFactory[] Factories = new JGroupsTGTFactory[AvailableNodeNames.length];
	ITGTAliasStore[] SpStores = new ITGTAliasStore[AvailableNodeNames.length];
	ITGTAliasStore[] IdpStores = new ITGTAliasStore[AvailableNodeNames.length];
	
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

	
	public void setNextBytesAnswer(byte[] bytes, long value) {
	    byte[] id = BigInteger.valueOf(value).toByteArray();
		System.arraycopy(id, 0, bytes, 0, (id.length < 30) ? id.length: 30);
	}
	
	
	@After
	public void after() throws Exception {
		for (int i = 0; i < AvailableNodeNames.length; ++i) {
			if (Factories[i] != null) {
                //_oLogger.debug("Cleaning factory " + i);
				//cleanTheFactory(Factories[i]);
				Factories[i].stop();
				Factories[i] = null;
				SpStores[i] = null;
				IdpStores[i] = null;
			}
		}		
	}
	
	@Test
	public void test0_FillBytesUnique() {
		long firstValue = 1l;
		
		byte[] firstId = new byte[ITGT.TGT_LENGTH];
		setNextBytesAnswer(firstId, firstValue);

		byte[] nextId = new byte[ITGT.TGT_LENGTH];
		for (long nextValue = firstValue + 1; nextValue < MAX_FILLBYTES_VALUE; ++nextValue) {
			setNextBytesAnswer(nextId, nextValue);
			if (Arrays.equals(nextId, firstId)) {
				_oLogger.error("Id's are equal for nextValue " + nextValue);
			}
			assertThat(Arrays.equals(nextId, firstId), equalTo(false));
		}
		
	}
	
	/**
	 * Isolates problems related to serializability of JGroupsTGT
	 * @throws Exception
	 */
	@Test
	public void test01_JGroupsTGTSerializable() throws Exception {
		JGroupsTGTFactory oTGTFactory = createJGroupsTGTFactory(0, EXPIRATION_FOR_TEST, USE_BLOCKING_UPDATES, BLOCKING_TIMEOUT);
		JGroupsTGT oTGT = (JGroupsTGT) oTGTFactory.createTGT(mockedUser);
		
		try {
			SerializationUtils.serialize(oTGT);
		}
		catch (Exception e) {
			_oLogger.error("Object of class JGroupsTGT cannot be serialized", e);
			assertThat(true, equalTo(false)); // or the universe implodes
		}
	}
	
	
	/**
	 * Isolates basic problems with using a very simple ReplicatedHasMap
	 * @throws Exception
	 */
	@Test
	public void test02_BasicReplicatedHashMapWithStringStringMap() throws Exception {
		JChannel channel = createChannelFromConfig();
		//channel.connect("HashmapCluster");
		ReplicatedHashMap<String, String> map = new ReplicatedHashMap<String, String>(channel);

		map.setBlockingUpdates(true);
		map.put("test", "test");
		assertThat(map.get("test"), not(equalTo(null)));
		assertThat(map.size(), equalTo(1));
		map.clear();
		map.stop();
		channel.close();
	}
	

	/**
	 * Isolates basic problems with using a ReplicatedHasMap for JGroupsTGT
	 * @throws Exception
	 */
	@Test
	public void test03_BasicReplicatedHashMapWithStringTGTMap() throws Exception {
		JChannel channel = createChannelFromConfig();
		//channel.connect("HashmapCluster");
		ReplicatedHashMap<String, JGroupsTGT> map = new ReplicatedHashMap<>(channel);
		JGroupsTGTFactory oTGTFactory = createJGroupsTGTFactory(0, EXPIRATION_FOR_TEST, USE_BLOCKING_UPDATES, BLOCKING_TIMEOUT);
		JGroupsTGT oTGT = (JGroupsTGT) oTGTFactory.createTGT(mockedUser);
		
		map.setBlockingUpdates(true);
		map.put("test", oTGT);
		JGroupsTGT retrievedTGT = map.get("test");
		retrievedTGT = map.get("test");
		assertThat(retrievedTGT, not(equalTo(null)));

		assertThat(map.size(), equalTo(1));
		map.clear();
		map.stop();
		channel.close();
	}
	
	
	@Test
	public void test04_OneNodeOneTGT() throws Exception {
        _oLogger.debug("test04_OneNodeOneTGT");
		testNTGTFactories(1, 1);
	}
	
	
	@Test
	public void test05_TwoNodesOneTGT() throws Exception {
		testNTGTFactories(2, 1);
	}
	
	
	@Test
	public void test06_FiveNodesOneTGT() throws Exception {
		testNTGTFactories(5, 1);
	}
	
	
	@Test
	public void test07_TwoNodesManyTGTs() throws Exception {
		testNTGTFactories(2, 100);
	}
	
	
	@Test
	public void test08_MaxNodesMaxTGTs() throws Exception {
		testNTGTFactories(AvailableNodeNames.length, (int)MAX_FILLBYTES_VALUE);
	}
	
	
	@Test
	public void test08a_MaxNodesManyTGTs() throws Exception {
		testNTGTFactories(AvailableNodeNames.length, (int)1000);  // TODO: increase and analyze
		_oLogger.info("Total number of unique TGTs: " + Factories[0].size());
	}
	
	
	/**
	 * keep this test switched off under normal circumstances, it is more a performance test
	 * @throws Exception
	 */
	//@Test
	public void test08b_TestHowManyItWillDo() throws Exception {
        reportMemory();
		testNTGTFactories(2, (int)75000);  // TODO: increase and analyze
		_oLogger.debug("Total number of unique TGTs: " + Factories[0].size());
        reportMemory();
	}
	
	
	@Test
	public void test09_RunTwoNodesAndAddOne() throws Exception {
		final int nTGTs = 100;
		final int expectedTGTs = nTGTs * 2;
		testNTGTFactories(2, nTGTs);
		assertThat(Factories[0].size(), equalTo(expectedTGTs));
		assertThat(Factories[1].size(), equalTo(expectedTGTs));
		assertThat(Factories[2], equalTo(null));
		createFactory(2);
		JGroupsTGTFactory addedFactory = Factories[2];
		assertThat(addedFactory, not(equalTo(null)));
		assertThat(addedFactory.size(), equalTo(expectedTGTs));
		JGroupsTGT newTGT = (JGroupsTGT) addedFactory.createTGT(mockedUser);
		addedFactory.persist(newTGT);
		assertThat(addedFactory.size(), equalTo(expectedTGTs + 1));
		assertThat(Factories[0].size(), equalTo(expectedTGTs + 1));
		assertThat(Factories[1].size(), equalTo(expectedTGTs + 1));
	}
	
	
	@Test
	public void test10_RunTwoNodesAddOneAndStopStartOne() throws Exception {		
		final int nTGTs = 100;
		final int expectedTGTs = nTGTs * 2;
		testNTGTFactories(2, nTGTs);
		createFactory(2);
		assertThat(Factories[2].size(), equalTo(expectedTGTs));
		JGroupsTGTFactory restartFactory = Factories[1];
		restartFactory.stop();
		JGroupsTGT newTGT = (JGroupsTGT) Factories[0].createTGT(mockedUser);
		Factories[0].persist(newTGT);
		assertThat(Factories[2].size(), equalTo(expectedTGTs + 1));
		assertThat(restartFactory.size(), equalTo(expectedTGTs));
		restartFactory.start();
		assertThat(restartFactory.size(), equalTo(expectedTGTs + 1));
	}
	
    /**
     * Test removal of expired TGTs
     */
    @Test
    public void test11_RemoveExpiredTGT() throws Exception {
        JGroupsTGTFactory oTGTFactory = createJGroupsTGTFactory(0, 1000, USE_BLOCKING_UPDATES, BLOCKING_TIMEOUT);
        JGroupsTGT oTGT = (JGroupsTGT) oTGTFactory.createTGT(mockedUser);

        oTGTFactory.persist(oTGT);
        assertTrue(oTGTFactory.exists(oTGT.getId()));

		final String alias = SOME_ALIAS + "-sp";
		ITGTAliasStore spStore = oTGTFactory.getAliasStoreSP();
		oTGTFactory.getAliasStoreSP().putAlias(SP_TYPE, SOME_REQUESTOR, oTGT.getId(), alias);
		assertThat(spStore.isAlias(SP_TYPE, SOME_REQUESTOR, alias), equalTo(true));

		oTGTFactory.removeExpired();
        assertTrue(oTGTFactory.exists(oTGT.getId()));
		assertThat(spStore.isAlias(SP_TYPE, SOME_REQUESTOR, alias), equalTo(true));

        Thread.sleep(1000);

        oTGTFactory.removeExpired();
        
        if (!oTGTFactory.isBlockingUpdates()) {
            Thread.sleep(1000);
        }
        assertFalse(oTGTFactory.exists(oTGT.getId()));
		assertThat(spStore.isAlias(SP_TYPE, SOME_REQUESTOR, alias), equalTo(false));
    }
    
	private void testNTGTFactories(int nNodes, int nTGTs) throws Exception {
		int firstFreeNode = getFirstUnusedNode();
		if (firstFreeNode + nNodes > AvailableNodeNames.length) {
			_oLogger.error("Not enough unused nodes left");
			throw new Exception("Not enough unused nodes left");
		}
		
		/*if (nTGTs < 1 || nTGTs > MAX_FILLBYTES_VALUE) {
			_oLogger.error("Invalid number of TGTs: " + nTGTs);
			throw new Exception("Invalid number of TGTs: " + nTGTs);
		}*/

		for (int i = firstFreeNode; i < nNodes; ++i) {
			createFactory(i);
		}

		RetrieveRepeater slowRepeater = new RetrieveRepeater(10, 1000);
		RetrieveRepeater quickRepeater = new RetrieveRepeater(10, 10);
		
		int persisted = 0;
		for (int i = 0; i < nNodes; ++i) {
			for (int j = 0; j < nTGTs; ++j) {
				JGroupsTGT tgt = (JGroupsTGT) Factories[i].createTGT(mockedUser);
				Factories[i].persist(tgt);
                String requestor = i + "-" + SOME_REQUESTOR;
				for (int k = 0; k < nNodes; ++k) {
					//JGroupsTGT rTGT = Factories[k].retrieve(tgt.getId());
                    JGroupsTGT rTGT = quickRepeater.retrieve(Factories[k], tgt.getId());
                    if (rTGT == null) {
                        _oLogger.debug("No luck retrieving tgt '" + tgt.getId() + "', will wait for max 10 seconds");
                        rTGT = slowRepeater.retrieve(Factories[k], tgt.getId());
                    }
                    if (rTGT == null) {
                        _oLogger.error("=========== start of Factory dump due to upcoming error ==========");
                        Factories[i].stop();
                        _oLogger.error("=========== end of Factory dump due to upcoming error ==========");
                    }
					assertThat("Assertion failed at (i,j,k): " + i + "," + j + "," + k, rTGT, not(equalTo(null)));
					assertThat(rTGT.getId(), equalTo(tgt.getId()));
				}
				if (++persisted % 10000 == 0) {
					_oLogger.info("Persisted: " + persisted + "/" + (nNodes * nTGTs) + " (TGTs: " + Factories[0].size() + ")");
				};
				String alias = SOME_ALIAS + "-sp-" + j;
				SpStores[i].putAlias(SP_TYPE, requestor, tgt.getId(), alias);
				assertThat(SpStores[i].getAlias(SP_TYPE, requestor, tgt.getId()), equalTo(alias));
				for (int l = 0; l < nNodes; ++l) {
                    String rAlias = SpStores[l].getAlias(SP_TYPE, requestor, tgt.getId()); 
                    //String rAlias = quickRepeater.getAlias(SpStores[l], SP_TYPE, requestor, tgt.getId());
                    if (rAlias == null) {
                        _oLogger.debug("No luck getting alias '" + SP_TYPE + "-" + requestor + "-" + tgt.getId() + "', will wait for max 10 seconds");
                        rAlias = slowRepeater.getAlias(SpStores[l], SP_TYPE, requestor, tgt.getId());
                    }
                    if (rAlias == null) {
                        _oLogger.error("=========== start of Factory dump due to upcoming error ==========");
                        Factories[i].stop();
                        _oLogger.error("=========== end of Factory dump due to upcoming error ==========");
                    }
					assertThat("Fails for node (i,j,l): " + i + "," + j + "," + l, rAlias, equalTo(alias));
				}
				alias = SOME_ALIAS + "-idp-" + j;
				IdpStores[i].putAlias(IDP_TYPE, requestor, tgt.getId(), alias);
				assertThat("Fails for node (i,j): " + i + "," + j, IdpStores[i].getAlias(IDP_TYPE, requestor, tgt.getId()), equalTo(alias));
				for (int l = 0; l < nNodes; ++l) {
					String rAlias = IdpStores[l].getAlias(IDP_TYPE, requestor, tgt.getId());
                    //String rAlias = quickRepeater.getAlias(IdpStores[l], IDP_TYPE, requestor, tgt.getId());
                    if (rAlias == null) {
                        _oLogger.debug("No luck getting alias '" + IDP_TYPE + "-" + requestor + "-" + tgt.getId() + "', will wait for max 10 seconds");
                        rAlias = slowRepeater.getAlias(IdpStores[l], IDP_TYPE, requestor, tgt.getId());
                    }
                    if (rAlias == null) {
                        _oLogger.error("=========== start of Factory dump due to upcoming error ==========");
                        Factories[i].stop();
                        _oLogger.error("=========== end of Factory dump due to upcoming error ==========");
                    }
					assertThat("Fails for node (i,j,l): " + i + "," + j + "," + l, rAlias, equalTo(alias));
				}
			}
		}
		for (int i = 0; i < nNodes; ++i) {
			assertThat(Factories[i].size(), equalTo(persisted));
 		}
		
		//quickRepeater.logReport(_oLogger);
		//slowRepeater.logReport(_oLogger);
	}

	private void createFactory(int i) throws Exception {
		Factories[i] = createJGroupsTGTFactory(i, EXPIRATION_FOR_TEST, USE_BLOCKING_UPDATES, BLOCKING_TIMEOUT);
		SpStores[i] = Factories[i].getAliasStoreSP();
		IdpStores[i] = Factories[i].getAliasStoreIDP();		
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
	
	private void cleanTheFactory(JGroupsTGTFactory oTGTFactory) throws Exception {
		Set<Entry<String, JGroupsTGT>> entries = oTGTFactory.entrySet();
		for (Entry<String, JGroupsTGT> entry: entries) {
			oTGTFactory.clean(entry.getValue());
		}
	}
	
	private JGroupsTGTFactory createJGroupsTGTFactory(int n, long expiration, boolean blockingUpdates, long timeout) throws Exception
	{
		String id = AvailableNodeNames[n];
		System.setProperty(JGroupsCluster.PROP_ASIMBA_NODE_ID, id);

		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG);

		Element eClusterElement = oConfigManager.getSection(
				null, "cluster", "id=test");
		assertThat(eClusterElement, not(equalTo(null)));

		Element eAliasClusterElement = oConfigManager.getSection(
				null, "alias-cluster", "id=test-alias");
		assertThat(eAliasClusterElement, not(equalTo(null)));

		JGroupsCluster oCluster = new JGroupsCluster();
		oCluster.start(oConfigManager, eClusterElement);
		JChannel jChannel = (JChannel) oCluster.getChannel();
		jChannel.connect("Something");
		assertThat(jChannel, not(equalTo(null)));
		_oLogger.info("JCluster address:" + jChannel.getAddressAsString());
		JGroupsCluster oAliasCluster = new JGroupsCluster();
		oAliasCluster.start(oConfigManager, eAliasClusterElement);

		JGroupsTGTFactory oTGTFactory = Factories[n] = new JGroupsTGTFactory();
		oTGTFactory.startForTesting(oConfigManager, eClusterElement, oCluster, oAliasCluster,
				mockedSecureRandom, expiration != 0 ? expiration : EXPIRATION_FOR_TEST, blockingUpdates, timeout);

		return oTGTFactory;
	}
	
	private JChannel createChannelFromConfig() throws Exception{
		IConfigurationManager oConfigManager = readConfigElementFromResource(FILENAME_CONFIG);

		Element eClusterElement = oConfigManager.getSection(
                null, "cluster", "id=test");            
		assertThat(eClusterElement, not(equalTo(null)));
		
		JGroupsCluster cluster = new JGroupsCluster();
		cluster.start(oConfigManager, eClusterElement);
		JChannel jChannel = (JChannel) cluster.getChannel();
		
		return jChannel;
	}
	
	
	private IConfigurationManager readConfigElementFromResource(String filename) throws Exception
	{
		
		InputStream oIS = JGroupsTGTFactory.class.getClassLoader().getResourceAsStream(filename);
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
	
    private void reportMemory() {
        final int MegaBytes = 10241024;
        long freeMemory = Runtime.getRuntime().freeMemory() / MegaBytes;
        long totalMemory = Runtime.getRuntime().totalMemory() / MegaBytes;
        long maxMemory = Runtime.getRuntime().maxMemory() / MegaBytes;

        _oLogger.debug("Used Memory in JVM: " + (maxMemory - freeMemory));
        _oLogger.debug("freeMemory in JVM: " + freeMemory);
        _oLogger.debug("totalMemory in JVM shows current size of java heap : "
                                   + totalMemory);
        _oLogger.debug("maxMemory in JVM: " + maxMemory);

    }
    
	private interface Store {
		public Object get() throws Exception;
	}
	
	private class RetrieveRepeater {
        public final static int TYPE_TGT = 1;
        public final static int TYPE_IDP = 2;
        public final static int TYPE_SP = 3;
		private int repeats;
		private int sleep;
		private int invocations;
		private int[] repetitions;
		private int failures;
        private int[] invocationsPerType = new int[4];
 		
		public RetrieveRepeater(int repeats, int sleep) {
			this.repeats = repeats;
			this.sleep = sleep;
			this.invocations = 0;
			this.failures = 0;
			this.repetitions = new int[repeats];
 		}
		
		public String getAlias(final ITGTAliasStore store, final String type, final String entityId, final String tgtId) throws Exception {
			return (String) repeat(new Store() {
				public Object get() throws Exception {
					return store.getAlias(type, entityId, tgtId);
				}
			});
		}
		
		public JGroupsTGT retrieve(final JGroupsTGTFactory factory, final String key) throws Exception {
			return (JGroupsTGT) repeat(new Store() {
				public Object get() throws Exception {
					return factory.retrieve(key);
				}
			});
		}
		
		private Object repeat(Store store) throws Exception {
            if (repeats <= 0) {
                return store.get();
            }
			int cycle = 0;
			Object result;
			
			invocations++;
			while ((result = store.get()) == null && cycle < this.repeats) {
				Thread.sleep(cycle * this.sleep);
				++cycle;
			}
			this.repetitions[cycle] += 1;
			
			if (result == null) {
				++failures;
                _oLogger.debug("failure for type: ");
			}
			
			return result;
		}
		
		public void logReport(Log logger) {
			logger.info("");
			logger.info(RetrieveRepeater.class.toString());
			logger.info("Invocations: " + invocations);
			logger.info("Successes per cycle (0 means direct succes):");
			for (int i = 0; i < repetitions.length; ++i) {
				logger.info("  " + i + " after " + (i * sleep) + " msecs: " + repetitions[i]);
			}
			logger.info("Failures: " + failures);
			logger.info("");
		}
	}
}
