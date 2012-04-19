
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
package com.alfaariss.oa.profile.aselect.business.requestor;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.profile.aselect.business.AuthNException;
import com.alfaariss.oa.profile.aselect.business.BusinessRuleException;
import com.alfaariss.oa.profile.aselect.business.beans.TGTInfo;

/**
 * Interface for requestor service business logic.
 * 
 * The requestor service can be used to initiate and verify authentication with
 * OpenASelect.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IRequestorService extends IAuthority
{
    /**
     * Initiate the authentication with OpenASelect.
     * 
     * Verifies the request and creates a authentication session with the given 
     * information. The session is persisted.
     * 
     * Forced log-on is supported by means of an forcedLogon parameter.
     *
     * OpenASelect country & language support is added by means of optional 
     * country and language parameters.
     * 
     * Forced UID and organization support is added by means of optional uid 
     * and remoteOrganization parameters.
     * 
     * @param sOaID The OA Server ID.
     * @param sRequestorID The Requestor ID.
     * @param sRemoteAddr The Requestor IP address.
     * @param sRequestorURL the requestor URL (for redirection 
     *  after authentication)
     * @param sRemoteOrganization The optional forced remote organization.
     * @param sForcedLogon Force authentication.
     * @param sUID The optional forced User ID.
     * @param sCountry The optional country.
     * @param sLanguage The optional language.
     * @param isSigned <code>true</code> if request is signed.
     * @param sPassive Passive authentication.
     * @return The created and persisted authentication session.
     * @throws BusinessRuleException If initiations fails due to 
     *  bussiness rule validation (user errors).
     * @throws OAException If initiations fails due to internal error.
     */
    public ISession initiateAuthentication(String sOaID, String sRequestorID,
        String sRequestorURL, String sRemoteOrganization, String sForcedLogon,
        String sUID, String sRemoteAddr, String sCountry, String sLanguage , 
        boolean isSigned, String sPassive) throws BusinessRuleException, OAException;

    /**
     * Verify the authentication with OpenASelect.
     * 
     * Verifies the request and credentials and returns the TGT/authentication
     * information.
     *     
     * @param sOaID The OA Server ID.
     * @param sRequestorID The Requestor ID.
     * @param sRemoteAddr The Requestor IP address.
     * @param sRID The session ID.
     * @param sCredentials The cerdentials.
     * @param isSigned <code>true</code> if request is signed.
     * @return The resolved TGT/authentication information.
     * @throws BusinessRuleException If verification fails due to 
     *  bussiness rule validation (user error).
     * @throws AuthNException If authentication fails (session state)
     * @throws OAException If initiations fails due to internal error.
     */
    public TGTInfo verifyAuthentication(String sOaID, String sRequestorID,
        String sRID, String sCredentials, String sRemoteAddr, boolean isSigned) 
        throws BusinessRuleException, AuthNException, OAException;
    
    /**
     * Initiate asynchronous logout.
     *
     * Verify the request and initiate the logout session.
     * 
     * @param sOaID The OAS ID
     * @param sRequestorID The application ID.
     * @param sCredentials The user's A-Select credentials as send to the 
     *  application during authentication. 
     * @param sRequestorURL The optional URL of the application to which the 
     *  user is sent after successful logging out.
     * @param sRemoteAddr The user its IP address.
     * @param isSigned <code>true</code> if request is signed.
     * 
     * @return The initiated logout session. 
     * @throws BusinessRuleException If logout initiation fails due to 
     *  business rule validation (user errors).
     * @throws OAException If logout initiation fails due to internal error.
     * @since 1.4
     */
    public ISession slo(String sOaID, String sRequestorID, String sCredentials,
        String sRequestorURL, String sRemoteAddr, boolean isSigned) 
        throws BusinessRuleException, OAException;
    
    /**
     * Perform a synchronous logout.
     *
     * Verify the request and remove the TGT session.
     * 
     * @param sRequestorID The application ID.
     * @param sCredentials The OAS credentials.
     * @param sRemoteAddr  The user its IP address.
     * @param isSigned <code>true</code> if request is signed.
     * @param reason The logout reason.
     * @return {@link RequestorEvent#LOGOUT_PARTIALLY} if successful.
     * @throws BusinessRuleException If logout fails due to 
     *  business rule validation (user errors).
     * @throws OAException If logout fails due to internal error.
     * @since 1.4
     */
    public String logout(String sRequestorID, String sCredentials, 
        String sRemoteAddr, boolean isSigned, String reason) 
        throws BusinessRuleException, OAException;
    
    /**
     * Check initialization state.
     * @return <code>true</code> if component is initialized.
     */
    public boolean isInitialized();

}