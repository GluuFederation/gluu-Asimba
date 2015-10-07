/*
 * oxAsimba is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2015, Gluu
 */
package org.gluu.asimba.util.ldap;

import java.util.List;
import org.gluu.site.ldap.persistence.annotation.LdapAttribute;
import org.gluu.site.ldap.persistence.annotation.LdapDN;
import org.gluu.site.ldap.persistence.annotation.LdapEntry;
import org.gluu.site.ldap.persistence.annotation.LdapObjectClass;
import org.xdi.ldap.model.BaseEntry;

/**
 * 
 * 
 * @author Dmitry Ognyannikov
 */
@LdapEntry
@LdapObjectClass(values = {"top", "oxAsimbaConfigurationEntry"})
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
