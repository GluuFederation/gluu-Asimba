/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
package org.asimba.auth.smsotp;

import java.io.Serializable;

/** 
 * Оne Time Password.
 */
public class OTP 
	implements Serializable
{
	private static final long serialVersionUID = 5618475706337833069L;
	
	private String _sValue = null;
	private Long _olTimeGenerated = null;
	private Long _olTimeSent = null;		// null if never sent
	private int _iTimesSent = 0;

	
	public boolean registerSent(Long olTimeSent)
	{
		_olTimeSent = (olTimeSent == null ? System.currentTimeMillis() : olTimeSent); 
		_iTimesSent++;
		
		return true;
	}
	
	public String getValue() {
		return _sValue;
	}
	
	public void setValue(String sValue) {
		_sValue = sValue;
	}
	
	public Long getTimeGenerated() {
		return _olTimeGenerated;
	}
	
	public void setTimeGenerated(Long olTimeGenerated) {
		_olTimeGenerated = olTimeGenerated;
	}
	
	public Long getTimeSent() {
		return _olTimeSent;
	}
	
	public void setTimeSent(Long olTimeSent) {
		_olTimeSent = olTimeSent;
	}
	
	public int getTimesSent() {
		return _iTimesSent;
	}
	
	public void setTimesSent(int iTimesSent) {
		_iTimesSent = iTimesSent;
	}
	
}
