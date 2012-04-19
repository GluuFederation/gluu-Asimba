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
package com.alfaariss.oa.util.saml2.storage.artifact;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;

/**
 * Singleton Factory that creates one instance of a {@link SAMLArtifactMap} 
 * implementation.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class ArtifactStoreFactory
{
    private Log _logger;
    private static SAMLArtifactMap _artifactStore;
    private static ArtifactStoreFactory _storeFactory;
    
    /**
     * Returns always the same instance of the AliasStoreFactory.
     * @return AliasStoreFactory The instance of this object.
     */
    public static ArtifactStoreFactory getInstance()
    {
        if (_storeFactory == null)
            _storeFactory = new ArtifactStoreFactory();
        return _storeFactory;
    }
    
    /**
     * Initializes the instance.
     * @param configurationManager The configuration manager.
     * @param config The artifact factory configuration.
     * @param cryptoManager The crypto manager.
     * @throws OAException If configuration is invalid.
     */
    public void init(IConfigurationManager configurationManager, Element config, 
        CryptoManager cryptoManager) throws OAException
    {
      //Start Artifact storage 
        Element eArtifactFactory = configurationManager.getSection(
            config, "artifactfactory");
        if(eArtifactFactory == null)
        {
            _logger.error(
                "'artifactfactory' configuration section not found"); 
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        IStorageFactory factory = 
            AbstractStorageFactory.createInstance(
                configurationManager, eArtifactFactory, 
                cryptoManager.getSecureRandom());
        try
        {
            _artifactStore = (SAMLArtifactMap)factory;
        }
        catch(ClassCastException e)
        {
            _logger.error(
                "Configured Artifact factory class isn't of type 'SAMLArtifactMap': " 
                + factory.getClass().getName());
            throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
        }           
    }
    
    /**
     * Returns always the same instance of the configured {@link SAMLArtifactMap}.
     *
     * @return The configured alias storage.
     * @throws OAException If store is not initialized.
     */
    public SAMLArtifactMap getStoreInstance() throws OAException
    {
        if(_artifactStore == null)
        {
            _logger.error("Artifact StorageFactory is not started yet"); 
            throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
        }
        return _artifactStore;
    }
    
    /**
     * Stop the factory and cleaner if initialized.
     */
    public void stop()
    {
        if(_artifactStore != null 
            && _artifactStore instanceof AbstractStorageFactory)
        {
            ((AbstractStorageFactory)_artifactStore).stop();
        }
    }
    
    private ArtifactStoreFactory()
    {
        _logger = LogFactory.getLog(ArtifactStoreFactory.class);
    }
}
