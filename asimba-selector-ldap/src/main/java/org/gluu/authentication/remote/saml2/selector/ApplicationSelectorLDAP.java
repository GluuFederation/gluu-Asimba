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
package org.gluu.authentication.remote.saml2.selector;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.authentication.remote.saml2.Warnings;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;
import java.util.HashMap;
import org.gluu.asimba.util.ldap.LDAPUtility;
import org.gluu.asimba.util.ldap.selector.ApplicationSelectorEntry;

/**
 * Asimba selector based on mapping from LDAP.
 * It do automatic mapping by entityId from request to organizationId 
 * 
 * @author Dmitry Ognyannikov, 2015
 */
public class ApplicationSelectorLDAP extends ApplicationSelector {

    private final static Log log = LogFactory.getLog(ApplicationSelectorLDAP.class);;

    private Map<String, String> applicationMappingLDAP;

    public ApplicationSelectorLDAP() {
        applicationMappingLDAP = new HashMap<>();
    }

    @Override
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException {
        super.start(oConfigurationManager, eConfig);
        loadApplicationMappingLDAP();
    }

    private void loadApplicationMappingLDAP() throws OAException {
        applicationMappingLDAP = new HashMap<>();
        
        try {
            List<ApplicationSelectorEntry> entries =  LDAPUtility.loadSelectors();
            // load LDAP entries
            for (ApplicationSelectorEntry entry : entries) {
                try {
                    String entityId = entry.getId();
                    String organizationId = entry.getOrganizationId();

                    if (!entry.isEnabled()) {
                        log.info("ApplicationSelector is disabled. Id: " + entityId + ", organizationId: " + organizationId);
                        continue;
                    }

                    if (applicationMappingLDAP.containsKey(entityId)) {
                        log.error("Duplicated ApplicationSelector. Id: " + entityId + ", organizationId: " + organizationId);
                        continue;
                    }

                    log.info("ApplicationSelector loaded. Id: " + entityId + ", organizationId: " + organizationId);
                    applicationMappingLDAP.put(entityId, organizationId);
                } catch (Exception e) {
                    log.error("Cannot read LDAP Selector, id: " + entry.getId(), e);
                }
            }
        } catch (Exception e) {
            log.error("Cannot read LDAP Selectors)");
        }
    }

    @Override
    public SAML2IDP resolve(HttpServletRequest oRequest, HttpServletResponse oResponse, ISession oSession,
        List<SAML2IDP> listOrganizations, String sMethodName, List<Warnings> oWarnings) throws OAException {

        String requestorId = oSession.getRequestorId();
        log.debug("Attempting to find mapping by requestorId: " + requestorId);

        String organizationId = this.applicationMappingLDAP.get(requestorId);
        if (organizationId != null) {
            log.debug("Found organizationId: " + organizationId + " by requestorId: " + requestorId);

            for (SAML2IDP org : listOrganizations) {
                if (org.getID().equals(organizationId)) {
                    return org;
                }
            }
        } else {
            log.debug("Can't find mapping by requestorId: " + requestorId);
        }

        // Not found, call super
        return super.resolve(oRequest, oResponse, oSession, listOrganizations, sMethodName, oWarnings);
    }


}
