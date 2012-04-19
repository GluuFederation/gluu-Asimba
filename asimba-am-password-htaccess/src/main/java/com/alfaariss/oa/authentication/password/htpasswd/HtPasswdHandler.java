/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.password.htpasswd;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractPasswordHandler;
import com.alfaariss.oa.authentication.password.IResourceHandler;

/**
 * HTPasswdHandler
 * 
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public class HtPasswdHandler extends AbstractPasswordHandler
{

    private final Log _logger;

    /**
     * Constructor
     */
    public HtPasswdHandler()
    {
        _logger = LogFactory.getLog(this.getClass());
    }

    /**
     * @see AbstractPasswordHandler#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager cm, Element eConfig)
        throws OAException
    {
        super.start(cm, eConfig);

        try 
        {
            Element eResourceSection = cm.getSection(
                eConfig, "resource");
            if (eResourceSection == null)
            {
                _logger.error("no htpasswd resource defined");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            while (eResourceSection != null)
            {
                IResourceHandler oProtocolHandler = new HtPasswordResource();
                oProtocolHandler.init(cm, eResourceSection);

                addResourceHandler(oProtocolHandler);

                //get next ProtocolResource section
                eResourceSection = cm.getNextSection(
                    eResourceSection);
            }

            setDefault(cm, eConfig);

        } 
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal(
                "Internal error during start of HTPasswordHandler", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
