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
package com.alfaariss.oa.api.logging;

/**
 * Interface to be implemented by all classes that are considered to be authentication
 * authorities.
 * <br />
 * Authentication steps should only be logged at the point that the authentication state
 * changes. As not all classes are supposed to change this state, not all classes are
 * supposed to write authentication log information. Classes that change authentication
 * state are denoted 'Authentication Authorities'. Authentication Authority classes must
 * implement this interface and accordingly, implement the <code>getAuthority</code>
 * method, thereby returning the type of authority they represent.
 * <br /><br />
 * New authorities should be added with great caution. Usually, only the managing classes
 * are considered the real authorities, since these are in charge of changing the state.
 * <br /><br />
 * Usually, the authority name is somewhat equal to the class name. The prefix determines
 * the position in the authentication process, the remainder represents the role the
 * component plays in that part of the process. Delegation of authentication logging, i.e.
 * a component that performs logging on behalf of its managing component, thereby acting
 * as that managing component by returning its <code>Authority</code>, is strongly
 * discouraged and should only be used when there is no other option and logging is
 * absolutely crucial.
 *
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public interface IAuthority
{  
    //TODO convert this interface to annotation (@interface) (Erwin)
    
    /**
     * Method to be implemented by all authentication authorities.
     *
     * @return The appropriate <code>Authority</code> name.
 *
     */
    public String getAuthority();
}
