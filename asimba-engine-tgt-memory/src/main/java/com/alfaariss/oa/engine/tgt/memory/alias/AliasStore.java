/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
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
package com.alfaariss.oa.engine.tgt.memory.alias;

import java.util.Enumeration;
import java.util.Hashtable;

/**
 * Store for memory aliasses.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public class AliasStore
{
    private String _sStoreID;//type
    
    private Hashtable<AliasKey, Alias> _htIndexedOnAlias;
    private Hashtable<AliasKey, Alias> _htIndexedOnTGTID;
    
    /**
     * Constructor. 
     * @param sStoreID The unique store id
     */
    public AliasStore(String sStoreID)
    {
        _sStoreID = sStoreID;
        _htIndexedOnAlias = new Hashtable<AliasKey, Alias>();
        _htIndexedOnTGTID = new Hashtable<AliasKey, Alias>();
    }
    
    /**
     * Returns the store id.
     * @return store id
     */
    public String getID()
    {
        return _sStoreID;
    }
    
    /**
     * Returns an enumeration with all aliasses in this store.
     * @return All aliasses
     */
    public Enumeration<Alias> getAll()
    {
        return _htIndexedOnAlias.elements();
    }
    
    /**
     * Removes the alias specified.
     * 
     * @param requestorID the requestor id for this alias
     * @param alias the alias
     */
    public void remove(String requestorID, String alias)
    {
        AliasKey oAliasKey = new AliasKey(requestorID, alias);
        Alias oAlias = _htIndexedOnAlias.get(oAliasKey);
        if (oAlias != null)
        {
            _htIndexedOnAlias.remove(oAliasKey);
            _htIndexedOnTGTID.remove(
                new AliasKey(requestorID, oAlias.getTGTID()));
        }
    }
    
    /**
     * Removes the alias specified by TGT id and requestor.
     *
     * @param requestorID the requestor id for this alias
     * @param tgtID the TGT id
     */
    public void removeForTGT(String requestorID, String tgtID)
    {
        AliasKey oAliasKey = new AliasKey(requestorID, tgtID);
        Alias oAlias = _htIndexedOnTGTID.get(oAliasKey);
        if (oAlias != null)
        {
            _htIndexedOnTGTID.remove(new AliasKey(requestorID, tgtID));
            _htIndexedOnAlias.remove(
                new AliasKey(requestorID, oAlias.getAlias()));
        }
    }
    
    /**
     * Removes all aliasses specified by TGT id.
     *
     * @param tgtID the TGT id
     * @since 1.4
     */
    public void removeForTGT(String tgtID)
    {
        Enumeration<Alias> enumAliasses = _htIndexedOnAlias.elements();
        while (enumAliasses.hasMoreElements())
        {
            Alias alias = enumAliasses.nextElement();
            if (alias.getTGTID().equals(tgtID))
            {
                _htIndexedOnTGTID.remove(new AliasKey(alias.getRequestorID(), alias.getTGTID()));
                _htIndexedOnAlias.remove(new AliasKey(alias.getRequestorID(), alias.getAlias()));
            }
        }
    }
    
    /**
     * Adds or updates the alias.
     * 
     * @param requestorID the requestor id for this alias
     * @param tgtID the TGT id
     * @param alias the alias
     */
    public void put(String requestorID, String tgtID, String alias)
    {
        Alias oAlias = new Alias(tgtID, requestorID, alias);

        _htIndexedOnAlias.put(new AliasKey(requestorID, alias), oAlias);
        _htIndexedOnTGTID.put(new AliasKey(requestorID, tgtID), oAlias);
    }
    
    /**
     * Returns the alias specified.
     * 
     * @param requestorID the requestor id for this alias
     * @param tgtID the TGT id
     * @return String with the alias
     */
    public String getAlias(String requestorID, String tgtID)
    {
        Alias oAlias = _htIndexedOnTGTID.get(new AliasKey(requestorID, tgtID));
        if (oAlias != null)
            return oAlias.getAlias();
        
        return null;
    }
    
    /**
     * Returns the TGT id for the specified alias.
     *
     * @param requestorID the requestor id for this alias
     * @param alias the alias
     * @return String with the TGT id
     */
    public String getTGTID(String requestorID, String alias)
    {
        Alias oAlias = _htIndexedOnAlias.get(new AliasKey(requestorID, alias));
        if (oAlias != null)
            return oAlias.getTGTID();
        
        return null;
    }
    
    /**
     * Verifies if the supplied alias already exists.
     * 
     * @param requestorID the requestor id for this alias
     * @param alias the alias
     * @return TRUE if the alias already exists.
     */
    public boolean exist(String requestorID, String alias)
    {
        AliasKey oAliasKey = new AliasKey(requestorID, alias);
        return _htIndexedOnAlias.containsKey(oAliasKey);
    }
    
    /**
     * Removes the alias for the specific entity; if available.
     * 
     * @param entityID The entity ID for who the alias must be removed
     * @param tgtID The TGT ID
     */
    public void removeAlias(String entityID, String tgtID)
    {
        AliasKey oAliasKey = new AliasKey(entityID, tgtID);
        Alias oAlias = _htIndexedOnTGTID.get(oAliasKey);
        if (oAlias != null)
        {
            _htIndexedOnTGTID.remove(new AliasKey(oAlias.getRequestorID(), oAlias.getTGTID()));
            _htIndexedOnAlias.remove(new AliasKey(oAlias.getRequestorID(), oAlias.getAlias()));
        }
    }
}
