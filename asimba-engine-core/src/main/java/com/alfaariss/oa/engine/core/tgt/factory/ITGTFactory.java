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
import java.util.List;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.persistence.IEntityManager;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.poll.IPollable;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.ITGTListener;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.tgt.TGTException;

/**
 * An interface for TGT factories.
 *
 * Implementations of this interface can be used to generate and store 
 * <b>T</b>icket <b>G</b>ranting <b>T</b>ickets. These factories should be 
 * implemented using the abstract factory design pattern. 
 * 
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 * @param <E> The type of TGT. 
 */
public interface ITGTFactory<E extends ITGT> 
    extends IEntityManager<E>, IStorageFactory, IPollable, IAuthority
{
    /** The authority name of TGT Factory implementations. */
    public static final String AUTHORITY_NAME = "TGTFactory";
    
	/**
	 * Create a new empty TGT.
	 * @param user The owner of the TGT.
	 * @return ITGT The new TGT.
	 * @throws TGTException If creation fails.
	 */
	public ITGT createTGT(IUser user) throws TGTException;
    
    /**
     * @see IEntityManager#retrieve(java.lang.Object)
     */
    public E retrieve(Object id)
      throws PersistenceException;
    
    /**
     * Add a TGT listener.
     *
     * @param listener the listener
     * @since 1.1
     */
    public void addListener(ITGTListener listener);
    
    /**
     * Remove a TGT listener.
     *
     * @param listener The listener to be removed
     * @since 1.1
     */
    public void removeListener(ITGTListener listener);
    
    /**
     * Returns all TGT listeners. 
     * @return An unmodifyable list with TGT listeners.
     * @since 1.4
     */
    public List<ITGTListener> getListeners();
    
    /**
     * Adds or overwrites an alias.
     *
     * @param sType The alias type (must be one of the column vars that are public static in this class.
     * @param sRequestorID The requestor ID for which the alias applies.
     * @param sTGTID The TGT ID for which the alias applies.
     * @param sAlias The alias to be inserted.
     * @throws OAException If insertion fails.
     * @since 1.1
     */
    public void putAlias(String sType, String sRequestorID, String sTGTID,   
        String sAlias) throws OAException;
    
    /**
     * Retrieves an Alias of the supplied type.
     *
     * If the alias is not supplied then <code>null</code> is returned.
     * 
     * @param sType The type of the alias that must be retrieved.
     * @param sRequestorID The requestor ID on which the alias applies.
     * @param sTGTID The OA TGT ID.
     * @return The retrieved alias of the specified type.
     * @throws OAException if an internal error is occurred during retrieval.
     * @since 1.1
     */
    public String getAlias(String sType, String sRequestorID, String sTGTID) 
        throws OAException;
    
    /**
     * Returns the TGT ID.
     * 
     * @param sType The type of the alias that is supplied.
     * @param sRequestorID The requestor ID for which this Alias is unique. 
     * @param sAlias The alias.
     * @return the OA TGT ID
     * @throws OAException if an internal error is occurred during retrieval.
     * @since 1.1
     */
    public String getTGTID(String sType, String sRequestorID, String sAlias) 
        throws OAException;
    
    /**
     * Verifies if the alias already exists for the specified requestor.
     *
     * @param sType The alias type.
     * @param sRequestorID The requestor ID for which the alias applies.
     * @param sAlias The alias value.
     * @return TRUE if the alias exists.
     * @throws OAException If the query can't be executed.
     * @since 1.1
     */
    public boolean isAlias(String sType, String sRequestorID, String sAlias) 
        throws OAException;
    
    /**
     * Verify is the factory supports alias storage. 
     * @return TRUE if alias support is enabled.
     * @since 1.3
     */
    public boolean hasAliasSupport();
    
    /**
     * Returns the alias store that contains aliasses for requestors in the SP role. 
     * @return The alias store for requestors.
     * @since 1.4
     */
    public ITGTAliasStore getAliasStoreSP();
    
    /**
     * Returns the alias store that contains aliasses for IDP's in the IDP role. 
     * @return The alias store for remote IDP's.
     * @since 1.4
     */
    public ITGTAliasStore getAliasStoreIDP();
}