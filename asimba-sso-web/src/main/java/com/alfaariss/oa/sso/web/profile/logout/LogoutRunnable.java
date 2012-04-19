/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package com.alfaariss.oa.sso.web.profile.logout;

import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.ITGTListener;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.tgt.TGTListenerException;


/**
 * Runnable that supports running a TGT event from inside a Thread.
 * <br>
 * The runnable updates the state to the supplied <code>LogoutState</code> object.
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class LogoutRunnable implements Runnable
{   
    private ITGTListener _listener;
    private ITGT _tgt;
    private LogoutState _state;
    private String _sName;
    
    /**
     * Constructor. 
     * @param listener The TGT event listener
     * @param tgt The TGT that should be loggedout
     * @param state The logout state object to update state information to
     * @param sName The ID of this runnable 
     */
    public LogoutRunnable(ITGTListener listener, ITGT tgt, LogoutState state,
        String sName)
    {
        _listener = listener;
        _tgt = tgt;
        _state = state;
        _sName = sName;
        
        _state.add(_sName);
    }
    
    /**
     * @see java.lang.Runnable#run()
     */
    public void run()
    {   
        try
        {
            _listener.processTGTEvent(TGTListenerEvent.ON_REMOVE, _tgt);
            _state.set(_sName, new TGTEventError(UserEvent.USER_LOGGED_OUT));
        }
        catch (TGTListenerException e)
        {
            _state.set(_sName, e.getErrors());
        }
    }
}
