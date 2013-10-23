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
package com.alfaariss.oa.util.saml2.proxy;




/**
 * Shared attribute names.
 * 
 * Contains shared attribute names for use in proxy mode.
 *
 * @author MHO
 * @author Alfa & Ariss
 */
public class ProxyAttributes
{
    /** Human readable Requestor name: ProviderName (String) (saml-core-2.0-os r2080)*/
    public final static String PROVIDERNAME = "ProviderName";
    /** Proxy attribute: ProxyCount (Integer) (saml-core-2.0-os r2161)*/
    public final static String PROXYCOUNT = "ProxyCount";
    /** Proxy attribute: IDPList (List&lt;SAMLIDPEntry&gt;) (saml-core-2.0-os r2165)*/
    public final static String IDPLIST = "IDPList";
    /** Proxy attribute: RequestorIDs (List&lt;String&gt;) (saml-core-2.0-os r2168) */
    public final static String REQUESTORIDS = "RequestorIDs";
    /** Proxy attribute: GetComplete (String) (saml-core-2.0-os r2192)*/
    public final static String IDPLIST_GETCOMPLETE = "IDPList_GetComplete";
    
    /** Proxy attribute: AttributeConsumingServiceIndex (Integer) (saml-core-2.0-os r2073)*/
    public final static String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "AttributeConsumingServiceIndex";
    /** Proxy attribute: AuthnContextComparisonType (String) (saml-core-2.0-os r1812)*/
    public final static String AUTHNCONTEXT_COMPARISON_TYPE = "AuthnContextComparisonType";
    /** Proxy attribute: AuthnContextClassRefs (List<String>) (saml-core-2.0-os r1126)*/
    public final static String AUTHNCONTEXT_CLASS_REFS = "AuthnContextClassRefs";
    /** Proxy attribute: AllowCreate (Boolean) (saml-core-2.0-os r2123)*/
    public final static String ALLOW_CREATE = "AllowCreate";
    /** Proxy attribute: NameID (String) (saml-core-2.0-os r443)*/
    public final static String SUBJECT_NAMEID = "NameID";
    /** Proxy attribute: SPNameQualifier (String) (saml-core-2.0-os r451)*/
    public final static String SUBJECT_SP_NAME_QUALIFIER = "SPNameQualifier";
    /** Proxy attribute: NameQualifier (String) (saml-core-2.0-os r448)*/
    public final static String SUBJECT_NAME_QUALIFIER = "NameQualifier";
    /** Proxy attribute: NameFormat (String) (saml-core-2.0-os r455)*/
    public final static String SUBJECT_NAME_FORMAT = "NameFormat";
    
    /** Response proxy attribute: AuthnContextClassRef (String) (saml-core-2.0-os r1126)*/
    public final static String AUTHNCONTEXT_CLASS_REF = "AuthnContextClassRef";
    /** 
     * Response proxy attribute: AuthenticatingAuthorities (List<String>) (saml-core-2.0-os r1133)
     * Contains the list of AuthenticatingAuthorities that are responsible for the assertion
     * In proxy mode, this is both the Remote IDP, to which we add ourselves 
     */
    public final static String AUTHNCONTEXT_AUTHENTICATING_AUTHORITIES = "AuthenticatingAuthorities";
    
    // Asimba specific attributes to share between IDP Profile and SP behavior (RemoteSAML authentication)
    /** The added context to the request URL (_before_ the querystring starts) */
    public final static String PROXY_URLPATH_CONTEXT = "urlpath.context";
    /** The established entityId that we are pretending to be for a requestor */
    public final static String PROXY_SHADOWED_ENTITYID = "shadowed.entityId";
    
}
