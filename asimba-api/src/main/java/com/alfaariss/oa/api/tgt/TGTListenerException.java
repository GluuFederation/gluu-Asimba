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
package com.alfaariss.oa.api.tgt;

import java.util.Collections;
import java.util.List;
import java.util.Vector;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.persistence.PersistenceException;


/**
 * Exception for TGT Event Listeners.
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class TGTListenerException extends PersistenceException
{
    /** serialVersionUID */
    private static final long serialVersionUID = -4648440926762560191L;
    
    private List<TGTEventError> _listErrors;
    
    /**
     * Constructor. 
     * @param tgtEventError containing the error information.
     */
    public TGTListenerException(TGTEventError tgtEventError)
    {
        super(SystemErrors.ERROR_INTERNAL);
        _listErrors = new Vector<TGTEventError>();
        _listErrors.add(tgtEventError);
    }
    
    /**
     * Constructor. 
     * @param tgtEventError containing the error information.
     */
    public TGTListenerException(List<TGTEventError> tgtEventError)
    {
        super(SystemErrors.ERROR_INTERNAL);
        _listErrors = tgtEventError;
    }
    
    /**
     * Returns the TGT Event Error object.
     * @return The TGTEventError object.
     */
    public TGTEventError getError()
    {
        return _listErrors.get(0);
    }
    
    /**
     * Returns the TGT Event Error object.
     * @return The TGTEventError object.
     */
    public List<TGTEventError> getErrors()
    {
        return Collections.unmodifiableList(_listErrors);
    }
    
    /**
     * @see java.lang.Throwable#getMessage()
     */
    public String getMessage()
    {
        return _listErrors.get(0).getCode().name();
    }
}
