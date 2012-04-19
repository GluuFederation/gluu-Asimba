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
package com.alfaariss.oa.api.session;

import java.util.List;
import java.util.Locale;

import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.user.IUser;

/**
 * Interface for a default authentication session.
 * 
 * A session may contain:
 * <ul>
 *  <li>User</li>
 *  <li>Authentication profile ID</li>
 *  <li>Requestor Object</li>
 *  <li>Session attributes</li>    
 * </ul>
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface ISession extends IEntity
{   
    /**
     * Size of a session id
     */
    public final static int ID_BYTE_LENGTH = 16;
    
    /**
     * The name of the session identifier.
     */
    public final static String ID_NAME = "asid";
    
    /**
     * The name of the locale.
     */
    public final static String LOCALE_NAME = "sessionLocale";
    
    /**
     * Retrieve the session id.
     * @return The id of this TGT.
     */
    public String getId(); 
   
    /**
     * Set a new authentication state.
     * @param state The new session authentication state.
     */
    public void setState(SessionState state);

    /**
     * Retrieve the session authentication state.
     * @return The session authentication state.
     */
    public SessionState getState();
    
    /**
     * Retrieve the requestor id.
     * @return The id of the requestor for which this authentication 
     *  session is created.
     */
    public String getRequestorId();
    
    /**
     * Retrieve the full profile URL.
     *
     * Retrieve the URL to redirect back to the profile.
     * @return The full profile URL.
     */
    public String getProfileURL();
    
    /**
     * Set a new full profile URL.
     * @param url The new profile URL.
     */
    public void setProfileURL(String url);
    
    /**
     * Retrieve the session its owner.
     * @return The user and owner of this session
     */
    public IUser getUser();
    
    /**
     * Set a new owner.
     * @param user The user and owner of this session
     */
    public void setUser(IUser user);
    
    /**
     * Retrieve the expiration time of this session.
     * @return The session expiration time.
     */
    public long getExpTime();
    
    /**
     * Set a new session expiration time.
     * @param expirationTime The new session expiration time.
     */
    public void setExpTime(long expirationTime);
    
    /**
     * Check if this session is expired.
     * @return <code>true</code> if this session is expired.
     */
    public boolean isExpired();    

    /**
     * Expire this session.
     */
    public void expire();
    
    /**
     * Retrieve the TGT id.
     * @return The id of this TGT.
     */
    public String getTGTId();
    
    /**
     * Set a new tgt id.
     * @param id The new id.
     */
    public void setTGTId(String id);
    
    /**
     * Retrieve the forced authentication mode.
     * @return <code>true</code> if this session uses 
     *  forced authentication.
     */
    public boolean isForcedAuthentication();
    
    /**
     * Set a new forced authentication mode.
     * @param enabled <code>true</code> if this session should use 
     *  forced authentication.
     */
    public void setForcedAuthentication(boolean enabled);
        
    /**
     * Retrieve the session attributes.
     * @return The attributes contained in the session.
     */
    public ISessionAttributes getAttributes();
    
    /**
     * Retrieve the selected authN profile.
     * <br>
     * Returns null if no profile is selected.
     * @return The iselected authN profile.
     */
    public IAuthenticationProfile getSelectedAuthNProfile();
    
    /**
     * Set the selected authN profile from the list.
     * @param profile The selected authN profile.
     */
    public void setSelectedAuthNProfile(IAuthenticationProfile profile);
    
    /**
     * Retrieve all authN profiles during this authN session.
     * <br>
     * This list may not be changed.
     * @return All authN profiles.
     */
    public List<IAuthenticationProfile> getAuthNProfiles();
    
    /**
     * Set the list with authN profiles during this authN session.
     * <br>
     * It also resets the currentAuthNProfile index to -1.
     * @param profiles A list with authentication profiles.
     */
    public void setAuthNProfiles(List<IAuthenticationProfile> profiles);
    
    /**
     * Returns the user id that must be used to identify the user.
     * @return The forced user id
     */
    public String getForcedUserID();
    
    /**
     * Set the forced user id, must be used for identification.
     * @param id The user id
     */
    public void setForcedUserID(String id);
    
    /**
     * The used locale during authentication. 
     * @param locale Locale object
     */
    public void setLocale(Locale locale);
    
    /**
     * Returns the authentication session wide locale. 
     * @return Locale object
     */
    public Locale getLocale();

    /**
     * Returns TRUE if passive authentication mode is enabled. 
     * @return TRUE when passive is enabled.
     * @since 1.5
     */
    public boolean isPassive();
    
    /**
     * Set to TRUE if the user must be authenticated passively.
     *
     * @param passive TRUE when passive must be enabled for this session
     * @since 1.5
     */
    public void setPassive(boolean passive);
}
