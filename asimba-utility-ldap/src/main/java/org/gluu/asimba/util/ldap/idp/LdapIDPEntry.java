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

import org.gluu.site.ldap.persistence.annotation.LdapAttribute;
import org.gluu.site.ldap.persistence.annotation.LdapEntry;
import org.gluu.site.ldap.persistence.annotation.LdapObjectClass;
import org.xdi.ldap.model.BaseEntry;
import lombok.Data;

/**
 * SAML2 IDP Entry for LDAP.
 * The LDAP container for IDPEntry.
 * 
 * @author Dmitry Ognyannikov
 */
@LdapEntry(sortBy = "uniqueIdentifier")
@LdapObjectClass(values = {"top", "oxAsimbaIDP"})
@Data
public class LdapIDPEntry extends BaseEntry {
    
    /**
     * The id of the organization.
     * 
     * It should be the entityID of remote IDP/ADFS
     */
    @LdapAttribute(name = "uniqueIdentifier", ignoreDuringUpdate = true)
    private String id;
    
    /**
     * The organization friendly name.
     */
    @LdapAttribute(name = "displayName")
    private String friendlyName;
    
    /**
     * The URL for the sourceId field value calculation.
     */
    @LdapAttribute(name = "displayName")
    private String identificationURL;
    
    @LdapAttribute
    private IDPEntry entry = new IDPEntry();
    
    public void setEntry(IDPEntry entry) {
        this.entry = entry;
        if (entry != null) {
            this.id = entry.getId();
            this.friendlyName = entry.getFriendlyName();
            this.identificationURL = entry.getIdentificationURL();
        }
    }
}
