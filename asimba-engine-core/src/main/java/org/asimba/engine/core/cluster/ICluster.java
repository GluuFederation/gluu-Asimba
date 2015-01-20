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
 * Standard interface/wrapper for a Cluster (or JGroup Channel)
 * 
 * @since 1.3.1
 * @author mdobrinic
 */
public interface ICluster {

	/**
	 * Retrieve the ID of the cluster
	 * @return
	 */
	public String getID();
	
	
	/**
	 * Retrieve the implementation-specific reference to the channel to
	 * access the Cluster facility.<br/>
	 * i.e. JGroups JChannel instance.
	 * @return
	 */
	public Object getChannel();

	
	/**
	 * Close the connection with the cluster<br/>
	 * i.e. close the JGroups channel and set it to null, ensuring a new call to getChannel will
	 * result in a new and connected channel
	 */
	public void close();
	
}
