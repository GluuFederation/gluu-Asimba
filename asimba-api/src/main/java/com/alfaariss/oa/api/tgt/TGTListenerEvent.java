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
package com.alfaariss.oa.api.tgt;

/**
 * TGT ((ticket-granting ticket)) listener events.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public enum TGTListenerEvent
{
    /**
     * TGT created
     */
    ON_CREATE,
    /**
     * TGT updated
     */
    ON_UPDATE,
    /**
     * TGT removed
     */
    ON_REMOVE,
    /**
     * TGT expired
     */
    ON_EXPIRE
}
