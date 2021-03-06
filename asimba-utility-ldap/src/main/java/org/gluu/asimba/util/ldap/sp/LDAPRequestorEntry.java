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
import org.gluu.site.ldap.persistence.annotation.LdapJsonObject;
import org.gluu.persist.model.base.BaseEntry;

/**
 * The requestor LDAP entity.
 * The LDAP container for RequestorEntry.
 *
 * @author Dmitry Ognyannikov
 */
@LdapEntry(sortBy = "uniqueIdentifier")
@LdapObjectClass(values = {"top", "oxAsimbaSPRequestor"})
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
            this.setInum(entry.getInum());
            this.setId(entry.getId());
            this.setFriendlyName(entry.getFriendlyName());
        }
    }
    
    public void setInum(String inum) {
        this.inum = inum;
        this.getEntry().setInum(inum);
    }
    
    public void setId(String id) {
        this.id = id;
        this.getEntry().setId(id);
    }
    
    public void setFriendlyName(String friendlyName) {
        this.friendlyName = friendlyName;
        this.getEntry().setFriendlyName(friendlyName);
    }
    
    public void setUniqueIdentifier(String uniqueIdentifier) {
        setId(uniqueIdentifier);
    }
    
    public String getUniqueIdentifier() {
        return getId();
    }

    /**
     * @return the inum
     */
    public String getInum() {
        return inum;
    }

    /**
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * @return the friendlyName
     */
    public String getFriendlyName() {
        return friendlyName;
    }

    /**
     * @return the entry
     */
    public RequestorEntry getEntry() {
        return entry;
    }
}
