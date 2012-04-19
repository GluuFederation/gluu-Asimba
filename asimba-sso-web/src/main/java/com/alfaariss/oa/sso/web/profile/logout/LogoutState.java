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

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;

/**
 * The logout state object that contains the full logout state for a TGT.
 * <br>
 * All Threads (<code>LogoutRunnable</code>) containing TGT Event listeners will
 * report any state change for a specific TGT ID to this object. 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class LogoutState
{
    /** TGT_LOGOUT_RESULTS as: <code>List<TGTEventError>()</code> */
    public final static String SESSION_LOGOUT_RESULTS = "logoutResults";
    
    private static Log _logger;
    private Hashtable<String, List<TGTEventError>> _htResults;
    private int _iSize;
    private String _sSessionID;
    private ISessionFactory<?> _sessionFactory;
    private volatile boolean _bFinished;
    
    /**
     * Constructor.
     * @param sessionFactory The TGT Factory.
     * @param sessionID The logout session id.
     */
    public LogoutState(ISessionFactory sessionFactory, String sessionID)
    {
        _logger = LogFactory.getLog(LogoutState.class);
        _sessionFactory = sessionFactory;
        _sSessionID = sessionID;
        _htResults = new Hashtable<String, List<TGTEventError>>();
        _iSize = 0;
        _bFinished = false;
    }
    
    /**
     * Adds the initial state for a specific <code>LogoutRunnable</code>.
     * @param runnableID The ID of the <code>LogoutRunnable</code>.
     */
    synchronized public void add(String runnableID)
    {
        List<TGTEventError> listDefault = new Vector<TGTEventError>();
        listDefault.add(new TGTEventError(UserEvent.USER_LOGOUT_IN_PROGRESS));
        
        _htResults.put(runnableID, listDefault);
        _iSize++;
    }
    
    /**
     * Updates (overwrites) the state of a specific <code>LogoutRunnable</code>.
     *
     * @param runnableID runnableID The ID of the <code>LogoutRunnable</code>.
     * @param error The new state as TGTEventError
     */
    synchronized public void set(String runnableID, TGTEventError error)
    {
        List<TGTEventError> listError = new Vector<TGTEventError>();
        listError.add(error);
        _htResults.put(runnableID, listError);
        _iSize--;
        
        if (_iSize == 0)
        {
            storeResults();
            _bFinished = true;
        }
    }
    
    /**
     * Updates (overwrites) the state of a specific <code>LogoutRunnable</code>.
     *
     * @param runnableID runnableID The ID of the <code>LogoutRunnable</code>.
     * @param errors The new state as TGTEventError
     */
    synchronized public void set(String runnableID, List<TGTEventError> errors)
    {
        _htResults.put(runnableID, errors);
        _iSize--;
        
        if (_iSize == 0)
        {
            storeResults();
            _bFinished = true;
        }
    }

    /**
     * Verify if logout is completed. 
     * @return TRUE if logout is completed.
     */
    public boolean isFinished()
    {
        return _bFinished;
    }

    private void storeResults()
    {
        try
        {
            ISession session = _sessionFactory.retrieve(_sSessionID);
            if (session != null)
            {
                ISessionAttributes sessionAttributes = session.getAttributes();
                SessionState sessionState = SessionState.USER_LOGOUT_SUCCESS;
                UserEvent logoutResult = UserEvent.USER_LOGGED_OUT;
                                
                List<TGTEventError> listResults = new Vector<TGTEventError>();
                
                Enumeration<List<TGTEventError>> enumLists = _htResults.elements();
                while (enumLists.hasMoreElements())
                {
                    List<TGTEventError> listError = enumLists.nextElement();
                    
                    for (int i = 0; i < listError.size(); i++)
                    {
                        TGTEventError tgtEventError = listError.get(i);
                        logoutResult = tgtEventError.getCode();
                        
                        if (logoutResult != UserEvent.USER_LOGGED_OUT)
                        {
                            _logger.debug("Logout failed: " + logoutResult);
                            sessionState = SessionState.USER_LOGOUT_FAILED;
                            break;
                        }
                    }
                    
                    listResults.addAll(listError);
                }
                
                session.setState(sessionState);
                
                sessionAttributes.put(this.getClass(), SESSION_LOGOUT_RESULTS, listResults);
                
                session.persist();
                
                _logger.debug("Stored logout state results for session with ID: " + _sSessionID);
            }
        }
        catch (OAException e)
        {
            _logger.debug("Could not store logout results in session with id: " + _sSessionID, e);
        }
    }
}
