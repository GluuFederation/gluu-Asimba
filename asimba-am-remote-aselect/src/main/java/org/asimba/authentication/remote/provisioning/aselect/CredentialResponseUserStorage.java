/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2013 Asimba
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
 */package org.asimba.authentication.remote.provisioning.aselect;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Hashtable;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.attributes.AttributeHelper;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.remote.AbstractRemoteMethod;
import com.alfaariss.oa.authentication.remote.aselect.RemoteASelectMethod;
import com.alfaariss.oa.engine.core.attribute.UserAttributes;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.storage.external.IExternalStorage;

/**
 * CredentialResponseUserStorage is meant to use a request_credentials response
 * of an ASelect authentication for user provisioning 
 *
 * @author mdobrinic
 *
 */
public class CredentialResponseUserStorage implements IExternalStorage {

	/** Local logger instance */
	private Log _oLogger;
	
	private Hashtable<String, String> _htResponse = null;
	
	/** Decoded attributes from the Response */
	protected IAttributes _oAttributes = new UserAttributes();

	/**
	 * Build the instance based on a provided response
	 * @param htResponse the response as it was received from the IDP to use 
	 * for looking up user attributes
	 */
	public CredentialResponseUserStorage(Hashtable<String, String> htResponse) {
		_oLogger = LogFactory.getLog(CredentialResponseUserStorage.class);
		setHtResponse(htResponse);
	}
	
	/**
	 * Initialize the CredentialResponseUserStorage processor
	 */
	public void start(IConfigurationManager oConfigurationManager,
			Element eConfig) throws UserException 
	{
		return;
	}
	
	/**
	 * Helper to keep local attributes in sync with HtResponse parameters 
	 * @param htResponse
	 */
	protected void setHtResponse(Hashtable<String, String> htResponse) {
		_htResponse = htResponse;
		
		// Sync attributes:
		_oAttributes = new UserAttributes();
		
		try {
			if (_htResponse != null && _htResponse.containsKey(RemoteASelectMethod.PARAM_ATTRIBUTES)) {
				String sSerializedAttributes = _htResponse.get(RemoteASelectMethod.PARAM_ATTRIBUTES);
				_oAttributes = AttributeHelper.deserializeAttributes(
								sSerializedAttributes, AbstractRemoteMethod.CHARSET, _oAttributes);	
			}
		} catch (OAException e) {
			_oLogger.warn("Could not decode serialized attributes: "+e.getMessage());
		}
	}
	
	/**
	 * Investigate whether the provided sID is authenticated in the response 
	 * Note: no mapping/remappings is done, neither are any integrity checks perfomed
	 */
	public boolean exists(String sID) throws UserException {
		// No user when no response:
		if (_htResponse == null) return false;
		
		String sCredentialsUserId = _htResponse.get(RemoteASelectMethod.PARAM_UID);
		if (sCredentialsUserId == null) return false;
		
        //DD 2x URLDecode i.v.m. bug in A-Select 1.5
		String sDecodedUserId = null;
		try {
			sDecodedUserId = URLDecoder.decode(sCredentialsUserId, AbstractRemoteMethod.CHARSET);
			sDecodedUserId = URLDecoder.decode(sDecodedUserId, AbstractRemoteMethod.CHARSET);
		} catch (UnsupportedEncodingException e) {
			_oLogger.warn("Could not decode user id: "+e.getMessage());
			return false;
		}
		return sID.equals(sDecodedUserId);
	}

	/**
	 * Nothing to clean up.
	 */
	public void stop() {
		return;
	}

	
	/**
     * Establish attribute value for user with provided id.
     * This attribute is looked for in the attributes of the response statement
     * <br/><b>Note</b> An attribute can have a multi-value value; in this case the Object
     * will hold a Vector&lt;String&gt;. Otherwise, the value can be assumed to be
     * a String value.
     * <br/> 
     * <br/><b>Note</b> the provided UserID is ignored; the AttributeStatement(s) of the 
     * Assertion is/are used.
     * 
     * @return null if there was no field for the provided UserID
     * @see IExternalStorage#getField(java.lang.String, java.lang.String)
	 */
	public Object getField(String sId, String sField) throws UserException {
		return _oAttributes.get(sField);
	}

	/**
     * Establish all attribute values with a name in 'fields' from the assertion 
     * into a Hashtable
     * <br/><b>Note</b> An attribute can have a multi-value value; in this case the 
     * value Objects will hold a Vector&lt;String&gt;. Otherwise, the value can be assumed 
     * to be a String value.
     * <br/> 
     * <b>Note</b> the provided UserID is ignored; the AttributeStatement(s) of the 
     * Assertion is/are used.
     * 
     * @return map with all attribute->name values from all AttributeStatements
     * @see IExternalStorage#getFields(java.lang.String, java.util.List)	 */
	public Hashtable<String, Object> getFields(String id, List<String> lFields)
			throws UserException 
	{
		Hashtable<String, Object> htValues = new Hashtable<String, Object>();
		
		for (String sField: lFields) {
			Object o = _oAttributes.get(sField);
			
			if (o != null) {
				htValues.put(sField, o);
			}
		}
		
		return htValues;
	}

}
