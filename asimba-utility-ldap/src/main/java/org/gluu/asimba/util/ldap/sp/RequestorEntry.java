/*
 * Asimba Server
 * 
 * Copyright (c) 2015, Gluu
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

import java.util.Date;
import java.util.Properties;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import org.gluu.site.ldap.persistence.annotation.LdapAttribute;
import org.gluu.site.ldap.persistence.annotation.LdapEntry;
import org.gluu.site.ldap.persistence.annotation.LdapObjectClass;
import lombok.Data;

/**
 * The requestor entity.
 *
 * Reads requestor information from LDAP.
 *
 * @author Dmitry Ognyannikov
 */
@LdapEntry(sortBy = "uniqueIdentifier")
@LdapObjectClass(values = {"top", "oxAsimbaSPRequestor"})
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class RequestorEntry {
    /**
     * The entity id of the Requestor.
     */
    @LdapAttribute(name = "uniqueIdentifier", ignoreDuringUpdate = true)
    private String id;
    
    /**
     * The application friendly name.
     */
    @LdapAttribute
    private String friendlyName;
    
    /**
     * The parent pool id.
     */
    @LdapAttribute
    private String poolID;
    
    @LdapAttribute
    private Properties properties;
    
    @LdapAttribute
    private boolean enabled = true;
    
    @LdapAttribute
    private boolean signing = true;
    
    /**
     * Timestamp when Entry was last modified, or null when unknown.
     */
    @LdapAttribute
    private Date lastModified = new Date();

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
     * @return the signing
     */
    public boolean isSigning() {
        return signing;
    }

    /**
     * @param signing the signing to set
     */
    public void setSigning(boolean signing) {
        this.signing = signing;
    }

    /**
     * @return the poolID
     */
    public String getPoolID() {
        return poolID;
    }

    /**
     * @param poolID the poolID to set
     */
    public void setPoolID(String poolID) {
        this.poolID = poolID;
    }
}
