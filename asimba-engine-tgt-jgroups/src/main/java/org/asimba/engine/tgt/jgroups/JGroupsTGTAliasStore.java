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

import java.util.Iterator;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jgroups.blocks.ReplicatedHashMap;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;

/**
 * Manages a map of aliases, using a key like:<br/>
 * "prefix type requestorid alias" -&gt; tgtid
 * 
 * @author mdobrinic
 *
 */
public class JGroupsTGTAliasStore implements ITGTAliasStore {

	private static final Log _oLogger = LogFactory.getLog(JGroupsTGTAliasStore.class);
	
	private static final String INDEX_SEPARATOR = " ";
	private static final int IDX_PREFIX = 0;
	private static final int IDX_TYPE = 1;
	private static final int IDX_ENTITYID = 2;
	private static final int IDX_ALIAS = 3;
	
	private String _sPrefix;
	private ReplicatedHashMap<String, String> _oAliasMap;
	
	
	
	private JGroupsTGTFactory _oTGTFactory;
	
	/**
	 * Create a new JGroupsTGTAliasStore instance, that uses a specified
	 * prefix for the keying of its indexes; should be used to specify i.e. 
	 * 'sp' or 'idp'.
	 * 
	 * @param sPrefix string that must not include character ...
	 * 
	 */
	public JGroupsTGTAliasStore(String sPrefix, ReplicatedHashMap<String, String> oAliasMap,
			JGroupsTGTFactory oTGTFactory)
	{
		_sPrefix = sPrefix;
		_oAliasMap = oAliasMap;
		_oTGTFactory = oTGTFactory;
	}
	

	private String getPrefixTypeEntitySubKey(String sType, String sEntityID) {
		String[] aKey = {_sPrefix, sType, sEntityID};
		return StringUtils.join(aKey, INDEX_SEPARATOR);
	}
	
	
	private String getMapKey(String sType, String sEntityID, String sAlias) {
		String[] aKey = {getPrefixTypeEntitySubKey(sType, sEntityID), sAlias};
		return StringUtils.join(aKey, INDEX_SEPARATOR);
	}

	
	/**
	 * Add new alias to Store<br/>
	 * 
	 * @param sType required, must be non null, non empty value
	 * @param sEntityId required, must be non null, non empty value
	 * @param sAlias required, must be non null, non empty value
	 */
	@Override
	public void putAlias(String sType, String sEntityID, String sTGTID, String sAlias) throws OAException 
	{
		if (StringUtils.isEmpty(sType) ||
				StringUtils.isEmpty(sAlias) || 
				StringUtils.isEmpty(sEntityID)) {
			throw new IllegalArgumentException("Type, alias and entityId must be set.");
		}
		
		String sKey = getMapKey(sType, sEntityID, sAlias);
		_oAliasMap.put(sKey, sTGTID);
		
		JGroupsTGT oJGroupsTGT = _oTGTFactory.retrieve(sTGTID);
		oJGroupsTGT.registerAlias(sKey);
		_oTGTFactory.persist(oJGroupsTGT);
	}


	@Override
	public String getAlias(String sType, String sEntityID, String sTGTID) throws OAException 
	{
		JGroupsTGT oJGroupsTGT = _oTGTFactory.retrieve(sTGTID);
		
		if (oJGroupsTGT == null) {
			_oLogger.error("Integrity check failed: TGT must exist for ID "+sTGTID);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}
		
		List<String> lAliasList = oJGroupsTGT.getAliases();
		String sKeyPrefix = getPrefixTypeEntitySubKey(sType, sEntityID);
		
		for (String sKey: lAliasList) {
			if (sKey.startsWith(sKeyPrefix)) { // TODO check what was stored in lAliasLiast, should that not be the key + alias instead of just the alias?
				// split always results in 4 elements, because putAlias enforces this 
				// pref - type - req - alias => tgtid
				String[] aKeyElements = sKey.split(INDEX_SEPARATOR);
				
				return aKeyElements[IDX_ALIAS];
			}
		}
		
		return null;
	}

	@Override
	public String getTGTID(String sType, String sEntityID, String sAlias)
			throws OAException {
		String sKey = getMapKey(sType, sEntityID, sAlias);
		return _oAliasMap.get(sKey);
	}

	@Override
	public boolean isAlias(String sType, String sEntityID, String sAlias)
			throws OAException {
		String sKey = getMapKey(sType, sEntityID, sAlias);
		return _oAliasMap.containsKey(sKey);
	}

	@Override
	public void removeAlias(String sType, String sEntityID, String sAlias)
			throws OAException {
		// First remove from Alias map
		String sKey = getMapKey(sType, sEntityID, sAlias);
		String sTGTID = _oAliasMap.get(sKey);
		
		_oAliasMap.remove(sKey);
		
		// Next, also remove from TGT Alias List!
		JGroupsTGT oTGT = _oTGTFactory.retrieve(sTGTID);
		List<String> lAliasList = oTGT.getAliases();
		
		Iterator<String> iterAlias = lAliasList.iterator();
		while (iterAlias.hasNext()) {
			if (sKey.equals(iterAlias.next())) {
				iterAlias.remove();
				// only one should be in the list, so when found, be done.
				break;
			}
		}
	}

	@Override
	public void removeAll(String sEntityID, String sTGTID) throws OAException 
	{
		JGroupsTGT oTGT = _oTGTFactory.retrieve(sTGTID);
		List<String> lAliasList = oTGT.getAliases();
		
		Iterator<String> iterAlias = lAliasList.iterator();
		while (iterAlias.hasNext()) {
			String sKey = iterAlias.next();
			
			boolean bEntityIdMatches = false;
			String[] aKeyElements = sKey.split(INDEX_SEPARATOR);
			// This always has 4 elements:
			bEntityIdMatches = (aKeyElements[IDX_ENTITYID].equals(sEntityID));
			
			if (bEntityIdMatches) {
				_oLogger.debug("Removing alias with key '"+sKey+"'");
				iterAlias.remove();
				_oAliasMap.remove(sKey);
			}
		}	
	}


	public void setBlockingUpdates(boolean b) {
		_oAliasMap.setBlockingUpdates(b);
	}
	
	
	public void stop() {
		_oAliasMap.stop();
	}
	
	
	/**
	 * Remove all aliases for a TGT with the provided TGT ID
	 * @param sTGTID TGT to remove the aliases for
	 * @return
	 */
	public int remove(String sTGTID) {
		JGroupsTGT oTGT = null;
	
		try {
			oTGT = _oTGTFactory.retrieve(sTGTID);
		}
		catch (PersistenceException e) {
			_oLogger.error("Could not establish TGT for id "+sTGTID+": "+e.getMessage());
			return 0;
		}
			
		List<String> lAliasList = oTGT.getAliases();
		
		int iDeletedAliasesCount = 0;
		
		Iterator<String> iterAlias = lAliasList.iterator();
		while (iterAlias.hasNext()) {
			String sKey = iterAlias.next();
			
			boolean bPrefixMatches = false;
			String[] aKeyElements = sKey.split(INDEX_SEPARATOR);
			// This always has 4 elements:
			bPrefixMatches = (aKeyElements[IDX_PREFIX].equals(_sPrefix));
			
			if (bPrefixMatches) {
				_oLogger.debug("Removing alias with key '"+sKey+"'");
				iterAlias.remove();
				_oAliasMap.remove(sKey);
				
				iDeletedAliasesCount++;
			}
		}
		
		return iDeletedAliasesCount;
	}
	
}
