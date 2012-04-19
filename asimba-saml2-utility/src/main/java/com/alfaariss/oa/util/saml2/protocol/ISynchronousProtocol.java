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
package com.alfaariss.oa.util.saml2.protocol;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.util.saml2.StatusException;

/**
 * Interface for SAML2 protocol processors.
 *
 * Defines a method for processing protocol messages.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public interface ISynchronousProtocol
{
    /**
     * Process a protocol request.
     * 
     * The request is retrieved from the context and validated against the 
     * SAML2 specification and OA business rules. 
     * 
     * The constructed response and other properties are set in the context.
     * 
     * In case of an invalid request, the output message is constructed conform 
     * the SAML2 specification and a {@link StatusException} is thrown. 
     * 
     * @param context The message context.
     * @throws OAException If processing fails due to internal error.
     * @throws StatusException If processing fails due to invalid request.
     */
    public void processProtocol(
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, 
        SAMLObject> context) throws OAException, StatusException;
}
