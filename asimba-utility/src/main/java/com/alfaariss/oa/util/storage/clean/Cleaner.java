
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
package com.alfaariss.oa.util.storage.clean;

import org.apache.commons.logging.Log;

import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.storage.clean.ICleanable;

/**
 * A <code>Runnable</code> to clean up expired items.
 * 
 * Should be started in a seperate thread. Calls at the configured interval 
 * {@link ICleanable#removeExpired()}.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class Cleaner implements Runnable
{
    /**
     * The system logger.
     */
    private Log _logger;

    /**
     * Cleaning interval.
     */
    private long _lInterval = 0;

    /**
     * Cleaning context.
     */
    private ICleanable _context;

    /**
     * The cleaner will perform cleaning while this property is <code>true</code>.
     */
    private boolean _bGo = false;

    /**
     * Default constructor.
     * 
     * @param lInterval cleaning interval in milliseconds
     * @param context cleanable
     * @param logger logger
     */
    public Cleaner (long lInterval, ICleanable context, Log logger)
    {
        _logger = logger;
        _context = context;
        _lInterval = lInterval;
        _bGo = true;
    }

    /**
     * Cleans the expired items managed by the context.
     * 
     * Calls the {@link ICleanable#removeExpired()} method at the given
     * interval.
     * 
     * @see java.lang.Runnable#run()
     */
    public void run()
    {
        _logger.debug("Start cleaning with interval (ms): " + _lInterval);
        while (_bGo)
        {
            try
            {
                Thread.sleep(_lInterval);
                _context.removeExpired();
            }
            catch (InterruptedException eI)
            {
                // Do nothing if interrupted
            }
            catch (PersistenceException e)
            {
                _logger.error("Could not remove expired entities", e);        
            }
            catch (Exception e)
            {
                _logger.fatal("Could not remove expired entities", e);
            }
        }
    }

    /**
     * Stop this cleaner.
     * 
     * The cleaner could be sleeping, so interrupt the Thread if applicable.
     */
    public void stop()
    {
        _bGo = false;
        _logger.info("The cleaner has stopped");
    }

}