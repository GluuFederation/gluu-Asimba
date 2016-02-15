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

import java.util.Date;
import java.util.Properties;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import lombok.Data;

/**
 * The requestor entity.
 *
 * Reads requestor information from LDAP.
 *
 * @author Dmitry Ognyannikov
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class RequestorEntry {
    
    private String inum;
    
    /**
     * The entity id of the Requestor.
     */
    private String id;
    
    /**
     * The application friendly name.
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
    
    /**
     * The parent requestor pool ID.
     */
    private String poolID;
    
    private Properties properties;
    
    private boolean enabled = true;
    
    private boolean signing = true;
    
    /**
     * Timestamp when Entry was last modified, or null when unknown.
     */
    private Date lastModified = new Date();
}
