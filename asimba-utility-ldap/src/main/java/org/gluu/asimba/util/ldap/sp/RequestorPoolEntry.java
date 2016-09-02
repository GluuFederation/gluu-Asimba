/*
 * Asimba Server
 * 
 * Copyright (C) 2015, Gluu
 * Copyright (C) 2013 Asimba
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
 * gluu-Asimba - Serious Open Source SSO - More information on www.gluu.org
 * 
 */
package org.gluu.asimba.util.ldap.sp;

import java.io.Serializable;
import java.util.Date;
import java.util.Properties;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * The requestor pool entity.
 *
 * Reads pool information from LDAP.
 *
 * @author Dmitry Ognyannikov
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RequestorPoolEntry implements Serializable, Comparable<RequestorPoolEntry> {
    
    private String inum;
    
    /**
     * The entity id of the RequestorPool.
     */
    private String id;
    
    /**
     * the application friendly name.
     */
    private String friendlyName;
    
    private boolean enabled = true;
    
    /**
     * Timestamp when Entry was last modified, or null when unknown.
     */
    private Date lastModified = new Date();
    
    /**
     * Sets whether the IdP should force the user to reauthenticate. Boolean values will be marshalled to either "true"
     * or "false".
     */
    private boolean forcedAuthenticate = false;
    
    /** pre authorization profile id */
    private String preAuthorizationProfileID;
    
    /** post authorization profile id */
    private String postAuthorizationProfileID;
    
    /** attribute release policy id */
    private String attributeReleasePolicyID; 
    
    /** properties */
    private Properties properties;
    
    private String authenticationProfileIDs;
    
    private String requestors;

    /**
     * @return the inum
     */
    public String getInum() {
        return inum;
    }

    /**
     * @param inum the inum to set
     */
    public void setInum(String inum) {
        this.inum = inum;
    }

    /**
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * @param id the id to set
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * @return the friendlyName
     */
    public String getFriendlyName() {
        return friendlyName;
    }

    /**
     * @param friendlyName the friendlyName to set
     */
    public void setFriendlyName(String friendlyName) {
        this.friendlyName = friendlyName;
    }

    /**
     * @return the enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @param enabled the enabled to set
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @return the lastModified
     */
    public Date getLastModified() {
        return lastModified;
    }

    /**
     * @param lastModified the lastModified to set
     */
    public void setLastModified(Date lastModified) {
        this.lastModified = lastModified;
    }

    /**
     * @return the forcedAuthenticate
     */
    public boolean isForcedAuthenticate() {
        return forcedAuthenticate;
    }

    /**
     * @param forcedAuthenticate the forcedAuthenticate to set
     */
    public void setForcedAuthenticate(boolean forcedAuthenticate) {
        this.forcedAuthenticate = forcedAuthenticate;
    }

    /**
     * @return the preAuthorizationProfileID
     */
    public String getPreAuthorizationProfileID() {
        return preAuthorizationProfileID;
    }

    /**
     * @param preAuthorizationProfileID the preAuthorizationProfileID to set
     */
    public void setPreAuthorizationProfileID(String preAuthorizationProfileID) {
        this.preAuthorizationProfileID = preAuthorizationProfileID;
    }

    /**
     * @return the postAuthorizationProfileID
     */
    public String getPostAuthorizationProfileID() {
        return postAuthorizationProfileID;
    }

    /**
     * @param postAuthorizationProfileID the postAuthorizationProfileID to set
     */
    public void setPostAuthorizationProfileID(String postAuthorizationProfileID) {
        this.postAuthorizationProfileID = postAuthorizationProfileID;
    }

    /**
     * @return the attributeReleasePolicyID
     */
    public String getAttributeReleasePolicyID() {
        return attributeReleasePolicyID;
    }

    /**
     * @param attributeReleasePolicyID the attributeReleasePolicyID to set
     */
    public void setAttributeReleasePolicyID(String attributeReleasePolicyID) {
        this.attributeReleasePolicyID = attributeReleasePolicyID;
    }

    /**
     * @return the properties
     */
    public Properties getProperties() {
        return properties;
    }

    /**
     * @param properties the properties to set
     */
    public void setProperties(Properties properties) {
        this.properties = properties;
    }

    /**
     * @return the authenticationProfileIDs
     */
    public String getAuthenticationProfileIDs() {
        return authenticationProfileIDs;
    }

    /**
     * @param authenticationProfileIDs the authenticationProfileIDs to set
     */
    public void setAuthenticationProfileIDs(String authenticationProfileIDs) {
        this.authenticationProfileIDs = authenticationProfileIDs;
    }

    /**
     * @return the requestors
     */
    public String getRequestors() {
        return requestors;
    }

    /**
     * @param requestors the requestors to set
     */
    public void setRequestors(String requestors) {
        this.requestors = requestors;
    }

    @Override
    public int compareTo(RequestorPoolEntry entry) {
        return this.id.compareToIgnoreCase(entry.getId());
    }
}
