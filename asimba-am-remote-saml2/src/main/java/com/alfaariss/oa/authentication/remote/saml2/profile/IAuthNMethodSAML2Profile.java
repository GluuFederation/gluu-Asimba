/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.profile;

import org.asimba.util.saml2.assertion.SAML2TimestampWindow;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.StandardProfile;
import com.alfaariss.oa.util.saml2.SAML2ConditionsWindow;

/**
 * SAML AuthN profiles should implement this interface.
 *
 * @author mdobrinic
 * @author jre
 * @author Alfa & Ariss
 */
public interface IAuthNMethodSAML2Profile
{
    /**
     * Initialize the authentication profile.
     *
     * @param configManager Configuration manager to extract the config from.
     * @param config The xml element containing configuration for this profile.
     * @param entityDescriptor The metadata store.
     * @param mapper The ID mapper, maps internal to external IDs
     * @param orgStorage The organization storage
     * @param sMethodID The authentication method id
     * @param conditionsWindow Conditions acceptance window 
     * @param oAuthnInstantWindow Acceptance window for AuthnStmt/AuthnInstant value
     * @param oRemoteSAMLUserProvisioningProfile ProvisioningProfile to use when instantiating new
     *   users as a result of authentication at a remote IDP
     * @throws OAException If initialization fails.
     */
    public void init(IConfigurationManager configManager, Element config,
        EntityDescriptor entityDescriptor, IIDMapper mapper, 
        IIDPStorage orgStorage, String sMethodID, 
        SAML2ConditionsWindow conditionsWindow, SAML2TimestampWindow oAuthnInstantWindow,
        StandardProfile oRemoteSAMLUserProvisioningProfile)
        throws OAException;
    
    /**
     * Removes the object from memory.
     */
    public void destroy();

}
