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

import org.gluu.site.ldap.persistence.annotation.LdapAttribute;
import org.gluu.site.ldap.persistence.annotation.LdapEntry;
import org.gluu.site.ldap.persistence.annotation.LdapObjectClass;
import lombok.Data;
import org.gluu.site.ldap.persistence.annotation.LdapJsonObject;
import org.xdi.ldap.model.BaseEntry;

/**
 * The requestor LDAP entity.
 * The LDAP container for RequestorEntry.
 *
 * @author Dmitry Ognyannikov
 */
@LdapEntry(sortBy = "uniqueIdentifier")
@LdapObjectClass(values = {"top", "oxAsimbaSPRequestor"})
@Data
public class LDAPRequestorEntry extends BaseEntry {

    @LdapAttribute(ignoreDuringUpdate = true)
    private String inum;
    
    /**
     * The entity id of the Requestor.
     */
    @LdapAttribute(name = "uniqueIdentifier")
    private String id;
    
    /**
     * The application friendly name.
     */
    @LdapAttribute
    private String friendlyName;
    
    @LdapAttribute(name = "oxAsimbaEntry")
    @LdapJsonObject
    private RequestorEntry entry = new RequestorEntry();
    
    public void setEntry(RequestorEntry entry) {
        this.entry = entry;
        if (entry != null) {
            this.inum = entry.getInum();
            this.id = entry.getId();
            this.friendlyName = entry.getFriendlyName();
        }
    }
    
    public void setInum(String inum) {
        this.inum = inum;
        this.entry.setInum(inum);
    }
    
    public void setId(String id) {
        this.id = id;
        this.entry.setId(id);
    }
    
    public void setFriendlyName(String friendlyName) {
        this.friendlyName = friendlyName;
        this.entry.setFriendlyName(friendlyName);
    }
    
    public void setUniqueIdentifier(String uniqueIdentifier) {
        setId(uniqueIdentifier);
    }
    
    public String getUniqueIdentifier() {
        return getId();
    }
}
