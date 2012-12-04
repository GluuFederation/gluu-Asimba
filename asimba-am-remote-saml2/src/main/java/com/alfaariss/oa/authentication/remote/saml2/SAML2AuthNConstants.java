/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2;


/**
 * Constants used by the SAML2 authentication method.
 *
 * TODO -MG: merge with utility.saml2 SAML2Constants?
 * @author jre
 * @author Alfa & Ariss
 */
public class SAML2AuthNConstants
{
    /**
     * Parameter indicating whether a response is received by the ResponseEndpoint. This information
     * is useful to the WebBrowserSSOProfile in processing the message. Value of the parameter is a
     * Boolean(true), if a response is received or Boolean(false) if not.
     */
    public final static String RESPONSE_ENDPOINT_PARAM = "response";
    
    /**
     * Parameter for identification of the received SAMLResponse object that is stored by the
     * ResponseEndpoint and retrieved by the Profile.
     */
    public final static String SESSION_ATTRIBUTE_NAME = "saml_response_obj";
    
    /**
     * Identifier used to store the return URL submitted by the web application.
     */
    public final static String ATTR_TARGET = "target";
    
    /**
     * Session variable for forced proxy organizations, gathered from the SAML2 profile.
     * This list is made complete by using the GET_COMPLETE parameter. It can be used to
     * verify if an assertion is sent by one of the obligatory organizations.
     * 
     * The IDPList entry for the AuthN request can use the same values as were originally
     * received by the profile (ProxyAttributes.IDPLIST and ProxyAttributes.IDPLIST_GETCOMPLETE)
     * 
     * @see com.alfaariss.oa.util.saml2.proxy.ProxyAttributes
     */
    public static final String FORCED_ORGANIZATIONS = "SAML2_forced_proxy_organizations";
    
    /**
     * Unique AuthnRequest number that can be attached to SessionID for making RequestID unique.
     * This name is used for storing the ID prefix in the authentication session.
     */
    public final static String AUTHNREQUEST_ID_PREFIX = "AuthnRequestIDPrefix";
    
    /**
     * Length of RequestID part to be used to separate between session ID and
     * RequestID part, that together form RequestID.
     */
    public final static int REQUEST_ID_BYTE_SIZE = 16;
    
    /**
     * Returns the length in chars:
     * 1 (default prefix '_') + 16 (byte size) * 2 (for hex encoding) 
     */
    public final static int REQUEST_ID_LENGTH = 1 + 16 * 2;
}
