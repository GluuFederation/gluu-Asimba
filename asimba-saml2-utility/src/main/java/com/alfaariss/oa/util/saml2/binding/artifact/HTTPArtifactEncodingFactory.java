/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package com.alfaariss.oa.util.saml2.binding.artifact;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.util.saml2.binding.AbstractEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;
import com.alfaariss.oa.util.saml2.storage.artifact.ArtifactStoreFactory;

/**
 * Create a HTTP Artifact encoder.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class HTTPArtifactEncodingFactory extends AbstractEncodingFactory
{
    /** system logger */
    private static Log _logger = LogFactory.getLog(
        HTTPArtifactEncodingFactory.class);
    
    /**
     * Default protected constructor.
     * @param prop The bindings configuration properties.
     */
    public HTTPArtifactEncodingFactory(BindingProperties prop)
    {   
        super(prop);  
    }

    /**
     * Create a JSP based HTTP Artifact encoder.
     * @see AbstractEncodingFactory#getEncoder()
     */
    @Override
    public SAMLMessageEncoder getEncoder() throws OAException
    {
        try
        {            
            //Retrieve service
            SAMLArtifactMap artifactMap = 
                ArtifactStoreFactory.getInstance().getStoreInstance();
       
            String sPath = _prop.getProperty(
                SAMLConstants.SAML2_ARTIFACT_BINDING_URI, "path");

            JSPHTTPArtifactEncoder encoder = new JSPHTTPArtifactEncoder(
                sPath, artifactMap);
            
            Boolean boolPost = _prop.getBooleanProperty(
                SAMLConstants.SAML2_ARTIFACT_BINDING_URI, "post");
            encoder.setPostEncoding(boolPost);
            
            if (boolPost.booleanValue() && sPath == null)
            {
                _logger.error("No 'path' configured for binding");
                throw new OAException(SystemErrors.ERROR_INTERNAL);      
            }
            
            return encoder;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not create JSPHTTPArtifactEncoder", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);            
        }
    }

}
