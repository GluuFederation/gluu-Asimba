/*
 * Asimba Server
 * 
 * Copyright (C) 2015 Asimba
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
package org.asimba.engine.core.cluster;

/**
 * Standard interface to engine-wide configured cluster storage
 * 
 * Design is based on (and limited to be used with) JGroups.
 * 
 * @since 1.3.1
 * @author mdobrinic
 */
public interface IClusterStorageFactory {

	/**
	 * Retrieve a configured ICluster instance by name
	 * @param sClusterName
	 * @return
	 */
	public ICluster getCluster(String sClusterName);
	
}
