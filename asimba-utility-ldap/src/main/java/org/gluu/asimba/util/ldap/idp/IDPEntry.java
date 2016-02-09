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
package org.gluu.asimba.util.ldap.idp;

import java.util.Date;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import lombok.Data;

/**
 * SAML2 IDP Entry for XML/JSON.
 * 
 * @author Dmitry Ognyannikov
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class IDPEntry {
    
    /**
     * The id of the organization.
     * 
     * It should be the entityID of remote IDP/ADFS
     */
    private String id;
    
    /**
     * SourceID is a 20-byte sequence used by the artifact receiver to determine artifact issuer identity and the
     * set of possible resolution endpoints. 
     * The issuer constructs the SourceID component of the artifact by 
     * taking the SHA-1 hash of the identification URL. The hash value is NOT encoded into hexadecimal. 
     */
    private String sourceId;
    
    /**
     * The organization friendly name.
     */
    private String friendlyName;
    
    /**
     * The url of the metadata or NULL if none.
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
    
    private boolean enabled = true;
    
    /**
     * TRUE if ACS should be set as Index.
     */
    private boolean acsIndex = true;
    
    /**
     * TRUE if Scoping element must be send.
     */
    private boolean scoping = true;
    
    /**
     * TRUE if NameIDPolicy element must be send.
     */
    private boolean nameIdPolicy = true;
    
    /**
     * AllowCreate value or false if disabled.
     */
    private boolean allowCreate = true;
    
    /**
     * The NameIDFormat to be set in the NameIDPolicy 
     * or NULL if resolved from metadata.
     */
    private String nameIdFormat;
    
    /** 
     * indicates whether avoid including SubjectConfirmation
     * in an AuthnRequest to this IDP; used for compatibility with Microsoft ADFS.
     * Default should be false
     */
    private boolean avoidSubjectConfirmations = false;
    
    /**
     * indicates whether SSO should be disabled when authentication
     * is performed by this IDP.
     * Default should be false 
     */
    private boolean disableSSOForIDP = false;
    
    /**
     * Timestamp when SAML2IDP was last modified, or null when unknown.
     */
    private Date lastModified = new Date();
    
    /**
     * The URL for the sourceId field value calculation.
     */
    private String identificationURL;
    
    
    public IDPEntry() {}

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
     * @return the avoidSubjectConfirmations
     */
    public boolean isAvoidSubjectConfirmations() {
        return avoidSubjectConfirmations;
    }

    /**
     * @param avoidSubjConf the avoidSubjectConfirmations to set
     */
    public void setAvoidSubjectConfirmations(boolean avoidSubjectConfirmations) {
        this.avoidSubjectConfirmations = avoidSubjectConfirmations;
    }

    /**
     * @return the disableSSOForIDP
     */
    public boolean isDisableSSOForIDP() {
        return disableSSOForIDP;
    }

    /**
     * @param disableSSOForIDP the disableSSOForIDP to set
     */
    public void setDisableSSOForIDP(boolean disableSSOForIDP) {
        this.disableSSOForIDP = disableSSOForIDP;
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
     * @return the identificationURL
     */
    public String getIdentificationURL() {
        return identificationURL;
    }

    /**
     * @param identificationURL the identificationURL to set
     */
    public void setIdentificationURL(String identificationURL) {
        this.identificationURL = identificationURL;
    }
    
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("LdapIDPEntry [id=").append(id).append(", sourceId=").append(sourceId).append(", friendlyName=").append(friendlyName)
            .append(", metadataUrl=").append(metadataUrl).append(", metadataTimeout=").append(metadataTimeout).append(", metadataFile=").append(metadataFile)
            .append(", enabled=").append(enabled).append(", acsIndex=").append(acsIndex).append(", scoping=").append(scoping)
            .append(", nameIdPolicy=").append(nameIdPolicy).append(", allowCreate=").append(allowCreate).append(", nameIdFormat=").append(nameIdFormat)
            .append(", avoidSubjConf=").append(avoidSubjectConfirmations).append(", disableSSO=").append(disableSSOForIDP).append(", dateLastModified=").append(lastModified)
            .append(", identificationURL=").append(identificationURL)
            .append("]");
        return builder.toString();
    }
    
}