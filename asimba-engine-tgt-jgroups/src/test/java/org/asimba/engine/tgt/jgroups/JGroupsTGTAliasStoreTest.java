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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.jgroups.blocks.ReplicatedHashMap;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class JGroupsTGTAliasStoreTest {

	@Mock
	ReplicatedHashMap mockedHashMap;

	@Mock
	JGroupsTGTFactory mockedJGroupsTGTFactory;
	
	@Rule
	public ExpectedException exception = ExpectedException.none();



	@Before
	public void before() throws Exception
	{
		MockitoAnnotations.initMocks(this);

		JGroupsTGT mockedJGroupsTGT = Mockito.mock(JGroupsTGT.class);

		List<String> mockedAliasList = new ArrayList<>();

		String[] aKey = {"sp", "type", "entityId", "alias"};
		String sKey = StringUtils.join(aKey, " ");
		mockedAliasList.add(sKey);

		String[] aKey2 = {"sp", "type", "entityId2", ""};
		String sKey2 = StringUtils.join(aKey2, " ");
		mockedAliasList.add(sKey2);

		String[] aKey3 = {"sp", "type", "", ""};
		String sKey3 = StringUtils.join(aKey3, " ");
		mockedAliasList.add(sKey3);

		when(mockedJGroupsTGT.getAliases()).thenReturn(mockedAliasList);
		when(mockedJGroupsTGTFactory.retrieve("tgtId")).thenReturn(mockedJGroupsTGT);
		
	}

	@Test
	public void testGetAlias() throws Exception
	{
		JGroupsTGTAliasStore oJGroupsTGTAliasStore = 
				new JGroupsTGTAliasStore("sp", null, mockedJGroupsTGTFactory);

		String sAlias;

		// Correct alias is returned for the right type
		sAlias = oJGroupsTGTAliasStore.getAlias("type", "entityId", "tgtId");
		assertThat(sAlias, is("alias"));

		// No alias is returned for the wrong type
		sAlias = oJGroupsTGTAliasStore.getAlias("wrong-type", "entityId", "tgtId");
		assertThat(sAlias, is(nullValue()));

		// An empty alias is not allowed
		exception.expect(ArrayIndexOutOfBoundsException.class);
		sAlias = oJGroupsTGTAliasStore.getAlias("type", "entityId2", "tgtId");
		exception = ExpectedException.none();
		
		// A null value is returned for unknown entityId 
		sAlias = oJGroupsTGTAliasStore.getAlias("type", "unknown-entityId", "tgtId");
		assertThat(sAlias, is(nullValue()));
	}
	
	
	@Test
	public void testRemoveAliasesForTgt() throws Exception
	{
		JGroupsTGTAliasStore oJGroupsTGTAliasStore = 
				new JGroupsTGTAliasStore("sp", mockedHashMap, mockedJGroupsTGTFactory);

		// Test whether all the aliases are removed
		int numRemoved = oJGroupsTGTAliasStore.remove("tgtId");
		assertThat(numRemoved, is(equalTo(3)));
	}
	
}
