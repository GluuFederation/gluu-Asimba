/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package com.alfaariss.oa.engine.tgt.memory;

import java.util.Enumeration;
import java.util.Hashtable;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.tgt.memory.alias.AliasStore;

/**
 * Stores TGT aliasses in a Hashtable.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class MemoryTGTAliasStore implements ITGTAliasStore
{
    private Hashtable<String,AliasStore> _htAliasStores;
    
    /**
     * Constructor.
     */
    public MemoryTGTAliasStore()
    {
        _htAliasStores = new Hashtable<String, AliasStore>();
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#putAlias(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public void putAlias(String type, String requestorID, String tgtID,
        String alias) throws OAException
    {
        AliasStore store = _htAliasStores.get(type);
        if (store == null)
            store = new AliasStore(type);
        
        store.put(requestorID, tgtID, alias);
        
        _htAliasStores.put(type, store);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#getAlias(java.lang.String, java.lang.String, java.lang.String)
     */
    public String getAlias(String type, String requestorID, String tgtID)
        throws OAException
    {
        AliasStore store = _htAliasStores.get(type);
        if (store != null)
            return store.getAlias(requestorID, tgtID);
        
        return null;
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#getTGTID(java.lang.String, java.lang.String, java.lang.String)
     */
    public String getTGTID(String type, String requestorID, String alias)
        throws OAException
    {
        AliasStore store = _htAliasStores.get(type);
        if (store != null)
            return store.getTGTID(requestorID, alias);
        
        return null;
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#isAlias(java.lang.String, java.lang.String, java.lang.String)
     */
    public boolean isAlias(String type, String requestorID, String alias)
        throws OAException
    {
        AliasStore store = _htAliasStores.get(type);
        if (store != null)
            return store.exist(requestorID, alias);
        
        return false;
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#removeAlias(java.lang.String, java.lang.String, java.lang.String)
     */
    public void removeAlias(String type, String entityID, String alias) 
        throws OAException
    {
        AliasStore store = _htAliasStores.get(type);
        if (store != null)
            store.remove(entityID, alias);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#removeAll(java.lang.String, java.lang.String)
     */
    public void removeAll(String requestorID, String tgtID) throws OAException
    {
        Enumeration<AliasStore> enumStores = _htAliasStores.elements();
        while (enumStores.hasMoreElements())
        {
            enumStores.nextElement().removeAlias(requestorID, tgtID);
        }
    }
    /**
     * Cleans all aliasses for the specified tgt. 
     * @param tgtID the tgt id
     * @return number of cleaned aliasses
     */
    int remove(String tgtID)
    {
        int iReturn = 0;
        Enumeration<AliasStore> enumStores = _htAliasStores.elements();
        while (enumStores.hasMoreElements())
        {
            enumStores.nextElement().removeForTGT(tgtID);
            iReturn++;
        }
        return iReturn;
    }
}
