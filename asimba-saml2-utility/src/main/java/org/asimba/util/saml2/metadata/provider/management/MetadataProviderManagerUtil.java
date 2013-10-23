/*
 * Asimba Server
 * 
 * Copyright (C) 2013 Asimba
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
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package org.asimba.util.saml2.metadata.provider.management;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Utility class with helper functions for MetadataProvider Management
 * 
 * @author mdobrinic
 *
 */
public class MetadataProviderManagerUtil {

	private static Log _oLogger = LogFactory.getLog(MetadataProviderManagerUtil.class);
	
	
    /**
     * Helper to ensure that a MetadataProviderManager exists; will create one from the
     * definition from elConfig if it doesn't
     * @param sMPMId
     * @param oConfigManager
     * @param elConfig configuration section for instantiating new MPM; if null, 
     * 		a StandardMetadataProviderManager is created
     * @return when a new provider was created, true is returned; otherwise, false is returned.
     */
    public static boolean establishMPM(String sMPMId, IConfigurationManager oConfigManager, Element elConfig) {
        IMetadataProviderManager oMPM = MdMgrManager.getInstance().getMetadataProviderManager(sMPMId);
        if (oMPM == null) {
        	if (elConfig == null) {
        		_oLogger.info("Creating new StandardMetadataProviderManager: ('"+sMPMId+"')");
        		oMPM = new StandardMetadataProviderManager(sMPMId);
        	} else {
        		_oLogger.info("Creating new MetadataProviderManager (only StandardMetadataProviderManager supported now!)");
        		oMPM = new StandardMetadataProviderManager(sMPMId);
        	}
            
            MdMgrManager.getInstance().setMetadataProviderManager(sMPMId, oMPM);
            
            return true;
        } else {
        	_oLogger.info("Re-using existing MetadataProviderManager ('"+sMPMId+"')");
        	
        	return false;
        }
    }
}
