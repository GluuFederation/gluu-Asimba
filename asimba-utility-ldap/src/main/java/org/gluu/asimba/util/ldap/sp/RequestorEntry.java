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
 * The requestor entity.
 *
 * Reads requestor information from LDAP.
 *
 * @author Dmitry Ognyannikov
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RequestorEntry implements Serializable {
    
    private String inum;
    
    /**
     * The Requestor ID of this SAML2 requestor. This is the same as the SAML2 EntityID.
     */
    private String id;
    
    /**
     * The application friendly name.
     */
    private String friendlyName;
    
    /**
     * The url of the metadata or NULL if none.
     * 
     * Configure the URL where the metadata is retrieved from (preferably a https URL).
     */
    private String metadataUrl;
    
    /**
     * The timeout to be used in connecting the the url 
     * metadata or -1 when default must be used.
     */
    private int metadataTimeout = -1;
    
    /**
     * The location of the metadata file or NULL if none. 
     */
    private String metadataFile;
    
    /**
     * The parent requestor pool ID.
     */
    private String poolID;
    
    private Properties properties;
    
    private boolean enabled = true;
    /**
     * Configure whether signing is required for this requestor. When set to true, incoming requests without a signature will be rejected.
     */
    private boolean signing = true;
    
    /**
     * Timestamp when Entry was last modified, or null when unknown.
     */
    private Date lastModified = new Date();

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
     * @return the metadataUrl
     */
    public String getMetadataUrl() {
        return metadataUrl;
    }

    /**
     * @param metadataUrl the metadataUrl to set
     */
    public void setMetadataUrl(String metadataUrl) {
        this.metadataUrl = metadataUrl;
    }

    /**
     * @return the metadataTimeout
     */
    public int getMetadataTimeout() {
        return metadataTimeout;
    }

    /**
     * @param metadataTimeout the metadataTimeout to set
     */
    public void setMetadataTimeout(int metadataTimeout) {
        this.metadataTimeout = metadataTimeout;
    }

    /**
     * @return the metadataFile
     */
    public String getMetadataFile() {
        return metadataFile;
    }

    /**
     * @param metadataFile the metadataFile to set
     */
    public void setMetadataFile(String metadataFile) {
        this.metadataFile = metadataFile;
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
}
