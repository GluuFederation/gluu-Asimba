/*
 * oxAsimba is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2015, Gluu
 */
package org.gluu.asimba.util.ldap;

import java.util.Date;
import org.gluu.site.ldap.persistence.annotation.LdapAttribute;
import org.gluu.site.ldap.persistence.annotation.LdapEntry;
import org.gluu.site.ldap.persistence.annotation.LdapObjectClass;
import org.xdi.ldap.model.BaseEntry;

/**
 * SAML2 IDP Entry for LDAP.
 * 
 * @author Dmitry Ognyannikov
 */
@LdapEntry(sortBy = "dateLastModified")
@LdapObjectClass(values = {"top", "oxAsimbaIDPEntry"})
public class LdapIDPEntry extends BaseEntry {
    
    @LdapAttribute(name = "uniqueIdentifier", ignoreDuringUpdate = true)
    private String id;
    
    @LdapAttribute
    private String sourceId;
    
    @LdapAttribute
    private String friendlyName;
    
    @LdapAttribute
    private String metadataUrl;
    
    @LdapAttribute
    private int metadataTimeout = -1;
    
    @LdapAttribute
    private String metadataFile;
    
    @LdapAttribute
    private boolean enabled = true;
    
    @LdapAttribute
    private boolean acsIndex = true;
    
    @LdapAttribute
    private boolean scoping = true;
    
    @LdapAttribute
    private boolean nameIdPolicy = true;
    
    @LdapAttribute
    private boolean allowCreate = true;
    
    @LdapAttribute
    private String nameIdFormat;
    
    @LdapAttribute
    private boolean avoidSubjConf = false;
    
    @LdapAttribute
    private boolean disableSSO = false;
    
    @LdapAttribute
    private Date dateLastModified = new Date();
    
    
    
    public LdapIDPEntry() {}

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
     * @return the sourceId
     */
    public String getSourceId() {
        return sourceId;
    }

    /**
     * @param sourceId the sourceId to set
     */
    public void setSourceId(String sourceId) {
        this.sourceId = sourceId;
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
     * @return the acsIndex
     */
    public boolean isAcsIndex() {
        return acsIndex;
    }

    /**
     * @param acsIndex the acsIndex to set
     */
    public void setAcsIndex(boolean acsIndex) {
        this.acsIndex = acsIndex;
    }

    /**
     * @return the scoping
     */
    public boolean isScoping() {
        return scoping;
    }

    /**
     * @param scoping the scoping to set
     */
    public void setScoping(boolean scoping) {
        this.scoping = scoping;
    }

    /**
     * @return the nameIdPolicy
     */
    public boolean isNameIdPolicy() {
        return nameIdPolicy;
    }

    /**
     * @param nameIdPolicy the nameIdPolicy to set
     */
    public void setNameIdPolicy(boolean nameIdPolicy) {
        this.nameIdPolicy = nameIdPolicy;
    }

    /**
     * @return the allowCreate
     */
    public boolean isAllowCreate() {
        return allowCreate;
    }

    /**
     * @param allowCreate the allowCreate to set
     */
    public void setAllowCreate(boolean allowCreate) {
        this.allowCreate = allowCreate;
    }

    /**
     * @return the nameIdFormat
     */
    public String getNameIdFormat() {
        return nameIdFormat;
    }

    /**
     * @param nameIdFormat the nameIdFormat to set
     */
    public void setNameIdFormat(String nameIdFormat) {
        this.nameIdFormat = nameIdFormat;
    }

    /**
     * @return the avoidSubjConf
     */
    public boolean isAvoidSubjConf() {
        return avoidSubjConf;
    }

    /**
     * @param avoidSubjConf the avoidSubjConf to set
     */
    public void setAvoidSubjConf(boolean avoidSubjConf) {
        this.avoidSubjConf = avoidSubjConf;
    }

    /**
     * @return the disableSSO
     */
    public boolean isDisableSSO() {
        return disableSSO;
    }

    /**
     * @param disableSSO the disableSSO to set
     */
    public void setDisableSSO(boolean disableSSO) {
        this.disableSSO = disableSSO;
    }

    /**
     * @return the dateLastModified
     */
    public Date getDateLastModified() {
        return dateLastModified;
    }

    /**
     * @param dateLastModified the dateLastModified to set
     */
    public void setDateLastModified(Date dateLastModified) {
        this.dateLastModified = dateLastModified;
    }
    
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("LdapIDPEntry [id=").append(id).append(", sourceId=").append(sourceId).append(", friendlyName=").append(friendlyName)
            .append(", metadataUrl=").append(metadataUrl).append(", metadataTimeout=").append(metadataTimeout).append(", metadataFile=").append(metadataFile)
            .append(", enabled=").append(enabled).append(", acsIndex=").append(acsIndex).append(", scoping=").append(scoping)
            .append(", nameIdPolicy=").append(nameIdPolicy).append(", allowCreate=").append(allowCreate).append(", nameIdFormat=").append(nameIdFormat)
            .append(", avoidSubjConf=").append(avoidSubjConf).append(", disableSSO=").append(disableSSO).append(", dateLastModified=").append(dateLastModified)
            .append("]");
        return builder.toString();
    }
    
}
