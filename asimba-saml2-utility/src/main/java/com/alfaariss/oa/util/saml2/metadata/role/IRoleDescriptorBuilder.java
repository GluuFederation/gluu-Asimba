/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.util.saml2.metadata.role;

import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.xml.security.credential.UsageType;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;

/**
 * Builder for role descriptors.
 *
 * @author EVB
 * @author Alfa & Ariss
 * @param <RD> The concrete role descriptor type.
 */
public interface IRoleDescriptorBuilder<RD extends RoleDescriptor>
{    
    /**
     * Build the optional <code>ID</code>..
     *
     * Document-unique identifier for the element.
     * @throws OAException If reading from configuration fails.
     */
    public void buildID() throws OAException;
    
    /**
     * Build the mandatory <code>protocolSupportEnumeration</code>.
     *
     * Contains a whitespace-delimited set of URIs that identify the set 
     * of protocol specifications supported by the role element.
     * @throws OAException If building fails.
     */
    public void buildProtocolSupportEnumeration() throws OAException;
    
    /**
     * Build the optional <code>errorURL</code>.
     *
     * Optional URI attribute that specifies a location to direct a user for 
     * problem resolution and additional support related to this role.
     * 
     * @throws OAException OAException If building fails.
     */    
    public void buildErrorURL() throws OAException;
    
    /**
     * Build the optional <code>Extensions"</code>.
     * @throws OAException If generation fails.
     */
    public void buildExtensions() throws OAException;
    
    /**
     * Build the optional <code>KeyDescriptor</code> of type {@link UsageType#SIGNING}.
     * Optional sequence of elements that provides information about the 
     * cryptographic keys that the entity uses when acting in this role.
     *    
     * @param crypto The OA crypto manager. 
     * @param sEntityID The OA Server entityID
     * @throws OAException If generation fails.
     */
    public void buildSigningKeyDescriptor(CryptoManager crypto,
        String sEntityID) throws OAException;
    
    /**
     * Retrieve the builder result
     * @return The created role descriptor.
     */
    public RD getResult();

}
