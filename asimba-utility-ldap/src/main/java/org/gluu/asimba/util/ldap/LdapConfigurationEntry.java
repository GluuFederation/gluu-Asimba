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
package org.gluu.asimba.util.ldap;

import org.gluu.asimba.util.ldap.idp.LdapIDPEntry;
import java.util.List;
import org.gluu.site.ldap.persistence.annotation.LdapAttribute;
import org.gluu.site.ldap.persistence.annotation.LdapDN;
import org.gluu.site.ldap.persistence.annotation.LdapEntry;
import org.gluu.site.ldap.persistence.annotation.LdapObjectClass;
import org.xdi.ldap.model.BaseEntry;
import lombok.Data;
        
/**
 * IDPs configuration list for LDAP.
 * 
 * @author Dmitry Ognyannikov
 */
@LdapEntry
@LdapObjectClass(values = {"top", "oxAsimbaConfigurationEntry"})
@Data
public class LdapConfigurationEntry extends BaseEntry {
    
    @LdapDN
    private String dn;
    
    @LdapAttribute(name = "oxAsimbaIDPEntry")
    private List<String> idps;
    
    private List<LdapIDPEntry> idpEntries;
    
    public LdapConfigurationEntry() {}

    /**
     * @return the dn
     */
    public String getDn() {
        return dn;
    }

    /**
     * @param dn the dn to set
     */
    public void setDn(String dn) {
        this.dn = dn;
    }

    /**
     * @return the idps
     */
    public List<String> getIdps() {
        return idps;
    }

    /**
     * @param idps the idps to set
     */
    public void setIdps(List<String> idps) {
        this.idps = idps;
    }

    /**
     * @return the idpEntries
     */
    public List<LdapIDPEntry> getIdpEntries() {
        return idpEntries;
    }

    /**
     * @param idpEntries the idpEntries to set
     */
    public void setIdpEntries(List<LdapIDPEntry> idpEntries) {
        this.idpEntries = idpEntries;
    }
    
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("LdapConfigurationEntry [dn=").append(dn)
            .append("]");
        return builder.toString();
    }
}
