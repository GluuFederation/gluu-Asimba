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
package com.alfaariss.oa.util.saml2.storage.artifact;

import java.io.Serializable;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;

/**
 * Base class for OA ArtifactMapEntries.
 * @author EVB
 * @author Alfa & Ariss
 */
public class ArtifactMapEntry 
    implements SAMLArtifactMapEntry, Serializable
{    
    /** serialVersionUID */
    private static final long serialVersionUID = -3778113904639127355L;

    /** Artifact. */
    private String _artifact;
    /** Issuer Entity ID. */
    private String _issuer;
    /** Receiver Entity ID. */
    private String _relyingParty;
    /** Expiration time. */
    private DateTime _expirationTime;
    /** SAML message mapped to the artifact. */
    private SAMLObject _message;

    /**
     * Create empty <code>ArtifactMapEntry</code>.
     */
    public ArtifactMapEntry ()
    {
        super();
        _artifact = null;
        _issuer = null;
        _relyingParty = null;
        _expirationTime = new DateTime();
        _message = null;
    }

    /**
     * create a new <code>ArtifactMapEntry</code> using the given values.
     * 
     * @param artifact artifact associated with the message
     * @param issuer issuer of the artifact
     * @param relyingParty receiver of the artifact
     * @param expiration expiration time of the artifact
     * @param message SAML message mapped to the artifact
     */
    public ArtifactMapEntry (String artifact, String issuer,
        String relyingParty, long expiration, SAMLObject message)
    {
        super();
        _artifact = artifact;
        _issuer = issuer;
        _relyingParty = relyingParty;
        _expirationTime = new DateTime(expiration);
        _message = message;
    }

    /**
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry#getArtifact()
     */
    public String getArtifact()
    {
        return _artifact;
    }

    /**
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry#getIssuerId()
     */
    public String getIssuerId()
    {
        return _issuer;
    }

    /**
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry#getRelyingPartyId()
     */
    public String getRelyingPartyId()
    {
        return _relyingParty;
    }

    /**
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry#getSamlMessage()
     */
    public SAMLObject getSamlMessage()
    {
        return _message;
    }

    /**
     * @see org.opensaml.util.storage.ExpiringObject#getExpirationTime()
     */
    public DateTime getExpirationTime()
    {
        return _expirationTime;
    }

    /**
     * @see org.opensaml.util.storage.ExpiringObject#isExpired()
     */
    public boolean isExpired()
    {
        return _expirationTime.isBeforeNow();
    }

    /**
     * @see org.opensaml.util.storage.ExpiringObject#onExpire()
     */
    public void onExpire()
    {
        // The abstract storage factory handles expiration and cleanup        
    }

}