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
package com.alfaariss.oa.api.datastorage;

import javax.sql.DataSource;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.IOptional;

/**
 * Interface to be implemented by a datastore object used by the engine.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public interface IDataStorageFactory extends IOptional
{
    /**
     * Returns the DataSource used for model storage purposes.
     * 
     * @return a DataSource to the model store
     * @throws OAException if datasource could not be created
     */
    public DataSource createModelDatasource() throws OAException;
    
    /**
     * Returns the DataSource used for system storage purposes.
     * 
     * @return a DataSource to the system store
     * @throws OAException if datasource could not be created
     */
    public DataSource createSystemDatasource() throws OAException;
}
