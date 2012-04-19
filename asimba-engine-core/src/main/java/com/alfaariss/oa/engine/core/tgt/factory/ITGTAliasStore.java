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
package com.alfaariss.oa.engine.core.tgt.factory;
import com.alfaariss.oa.OAException;

/**
 * TGT Alias store interface. 
 * <br>
 * Can be used for TGT aliasses for requestors or for remote IDP's. 
 * @author MHO
 * @author Alfa & Ariss 
 * @since 1.4
 */
public interface ITGTAliasStore
{
    /**
     * Adds or overwrites an alias.
     *
     * @param sType The alias type (must be one of the column vars that are public static in this class.
     * @param sEntityID The entity ID (requestor/idp) for which the alias applies.
     * @param sTGTID The TGT ID for which the alias applies.
     * @param sAlias The alias to be inserted.
     * @throws OAException If insertion fails.
     */
    public void putAlias(String sType, String sEntityID, String sTGTID,   
        String sAlias) throws OAException;
    
    /**
     * Retrieves an Alias of the supplied type.
     *
     * If the alias is not supplied then <code>null</code> is returned.
     * 
     * @param sType The type of the alias that must be retrieved.
     * @param sEntityID The entity ID (requestor/idp) on which the alias applies.
     * @param sTGTID The OA TGT ID.
     * @return The retrieved alias of the specified type.
     * @throws OAException if an internal error is occurred during retrieval.
     */
    public String getAlias(String sType, String sEntityID, String sTGTID) 
        throws OAException;
    
    /**
     * Returns the TGT ID.
     * 
     * @param sType The type of the alias that is supplied.
     * @param sEntityID The entity ID (requestor/idp) for which this Alias is unique. 
     * @param sAlias The alias.
     * @return the OA TGT ID
     * @throws OAException if an internal error is occurred during retrieval.
     */
    public String getTGTID(String sType, String sEntityID, String sAlias) 
        throws OAException;
    
    /**
     * Verifies if the alias already exists for the specified requestor.
     *
     * @param sType The alias type.
     * @param sEntityID The entity ID (requestor/idp) for which the alias applies.
     * @param sAlias The alias value.
     * @return TRUE if the alias exists.
     * @throws OAException If the query can't be executed.
     */
    public boolean isAlias(String sType, String sEntityID, String sAlias) 
        throws OAException;
    
    /**
     * Removes a specific alias.
     *
     * @param sType The alias type (must be one of the column vars that are public static in this class.
     * @param sEntityID The entity ID (requestor/idp) for which the alias applies.
     * @param sAlias The alias to be removed.
     * @throws OAException If removal fails.
     */
    public void removeAlias(String sType, String sEntityID, String sAlias) 
        throws OAException;
    
    /**
     * Removes all aliasses available for the supplied requestor.
     *
     * @param sEntityID The entity ID (requestor/idp) for which the alias applies.
     * @param tgtID The OA TGT ID.
     * @throws OAException OAException If an internal error ocurres during removal.
     */
    public void removeAll(String sEntityID, String tgtID) throws OAException;
}