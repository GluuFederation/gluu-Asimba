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
package com.alfaariss.oa.util.saml2.metadata;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.RoleDescriptor;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.util.saml2.metadata.entitydescriptor.EntityDescriptorBuilder;
import com.alfaariss.oa.util.saml2.metadata.role.IRoleDescriptorBuilder;

/**
 * Construct metadata objects.
 * 
 * DD The creation of metadata is implemented using the builder design pattern, 
 * which allows constructing several {@link RoleDescriptor} objects.
 *  
 * The following steps should be taken to construct metadata objects:
 * <ol>
 *  <li>Create a builder.</li>
 *  <li>Create the <code>MetaDataDirector</code> with the created builder.</li>
 *  <li>Construct the metadata using the construct method of the director</li>
 *  <li>Retrieve product by calling <code>getResult()</code> of the builder</li>
 * </ol>
 * 
 * @author EVB
 * @author Alfa & Ariss
 * @see <a href="http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf" 
 *  target="_new">
 *  Metadata for the OASIS Security Assertion Markup Language (SAML) V2.0
 *  </a>
 */
public class MetaDataDirector
{
    /** system logger */
    private static Log _logger;
    
    private EntityDescriptorBuilder _builder;
    private IRoleDescriptorBuilder _roleBuilder;
    private CryptoManager _crypto;
    
    
    /**
     * create a new <code>MetaDataDirector</code>.
     *
     * @param builder The builder to be used. 
     * @param roleBuilder The builder to be used for role descriptors.
     * @param crypto The OA crypto engine. 
     */
    public MetaDataDirector(EntityDescriptorBuilder builder, 
        IRoleDescriptorBuilder roleBuilder, CryptoManager crypto)
    {
        _logger = LogFactory.getLog(MetaDataDirector.class);
        _builder = builder;
        _roleBuilder = roleBuilder;
        _crypto = crypto;        
    }
    
    /**
     * Construct a <code>EntityDescriptor</code>.
     * 
     * This director uses a {@link EntityDescriptorBuilder} to construct an 
     * <code>EntityDescriptor</code>. In addition {@link IRoleDescriptorBuilder}
     * instances are used to add role descriptor elements to the entity 
     * descriptor.
     * 
     * This method is not thread safe.
     * 
     * @throws OAException If creation fails.
     */
    public void constructMetadata() throws OAException 
    {
        try
        {
            _builder.buildEntityID();
            _builder.buildID();            
            _builder.buildValidUntil();
            _builder.buildCacheDuration();
                        
            //Add the role descriptor
            //ID is optional _roleBuilder.buildID();                         
            _roleBuilder.buildProtocolSupportEnumeration();
            _roleBuilder.buildExtensions();
            
            //DD If no private key is supplied (signing not configured) signing is omitted
            if(_crypto.getPrivateKey() != null)
            {         
                _builder.buildSignature(_crypto);
                _roleBuilder.buildSigningKeyDescriptor(_crypto, 
                    _builder.getResult().getEntityID());
            }
            RoleDescriptor roleDescriptor = _roleBuilder.getResult();
            List<RoleDescriptor> roles = _builder.getResult().getRoleDescriptors();           
            roles.add(roleDescriptor);
                        
            _builder.buildOrganization();
            _builder.buildContactPersons();
        }
        catch (OAException e)
        {
            _logger.warn("Could not construct EntityDescriptor", e);
            throw e;
        }
        catch (Exception e)
        {
            _logger.warn(
                "Could not construct EntityDescriptor due to internal error", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }             
    }
}
