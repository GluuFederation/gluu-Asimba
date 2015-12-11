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
import com.alfaariss.oa.authentication.remote.saml2.selector.DefaultSelector;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;

/**
 * Asimba selector based on mapping from LDAP.
 * It do automatic mapping by entityId from request to organizationId 
 * 
 * @author Dmitry Ognyannikov
 */
public class ApplicationSelectorLDAP extends DefaultSelector {

    private final static Log log = LogFactory.getLog(ApplicationSelectorLDAP.class);;

    private ApplicationSelectorConfigurationLDAP applicationSelectorConfiguration;
    private Map<String, String> applicationMapping;



    public ApplicationSelectorLDAP() {
        this.applicationSelectorConfiguration = new ApplicationSelectorConfigurationLDAP();
    }

    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException {
        super.start(oConfigurationManager, eConfig);
        loadApplicationMapping();
    }

    private void loadApplicationMapping() {
        this.applicationSelectorConfiguration.loadConfiguration();
        this.applicationMapping = this.applicationSelectorConfiguration.getApplicationMapping();
    }

    @Override
    public SAML2IDP resolve(HttpServletRequest oRequest, HttpServletResponse oResponse, ISession oSession,
        List<SAML2IDP> listOrganizations, String sMethodName, List<Warnings> oWarnings) throws OAException {

        String requestorId = oSession.getRequestorId();
        log.debug("Attempting to find mapping by requestorId: " + requestorId);

        String organizationId = this.applicationMapping.get(requestorId);
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

        SAML2IDP result = super.resolve(oRequest, oResponse, oSession, listOrganizations, sMethodName, oWarnings);

        return result;
    }


}
