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
package com.alfaariss.oa.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Utility class for serialization helper functions.
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class Serialize
{
    
    /**
    * Encodes an object for storage.
    * 
    * Encodes an object so it can be stored in the database.
    * @param o The object that needs to be encoded.
    * @return The encoded object.
     *@throws Exception If encoding fails.
    */
   public static byte[] encode(Object o) throws Exception
   {
       if(o == null)
           return null;
       
       byte[] baResponse = null;
       ByteArrayOutputStream osBytes = null;
       ObjectOutputStream osObject = null;
       try
       {
           osBytes = new ByteArrayOutputStream();
           osObject = new ObjectOutputStream(osBytes);
           osObject.writeObject(o);            
           baResponse = osBytes.toByteArray();
       }
       catch (Exception e)
       {
           throw e;
       }
       finally
       {
           
           try
           {
               if(osObject != null)
                   osObject.close();
           }
           catch (IOException e)
           {
           }
           
           try
           {
               if(osBytes!= null)
                   osBytes.close();
           }
           catch (IOException e)
           {
           }            

       }
       
       return baResponse;
   }

   /**
    * Decodes an object.
    * <br>
    * Decodes an object that is returned from the database.
    * 
    * @param baBytes the bytes to be decoded.
    * @return The decoded <code>Object</code>.
    * @throws Exception if decoding fails.
    */
   public static Object decode(byte[] baBytes) throws Exception
   {
       if(baBytes == null)
           return null;
       
       Object oResponse = null;
       ByteArrayInputStream isBytes = null;
       ObjectInputStream isObject = null;
       try
       {
           isBytes = new ByteArrayInputStream(baBytes);
           isObject = new ObjectInputStream(isBytes);
           oResponse = isObject.readObject();
       }
       catch (Exception e)
       {
           throw e;
       }
       finally
       {
           try
           {
               if(isObject != null)
                   isObject.close();
           }
           catch (IOException e)
           {
           }
           
           try
           {
               if(isBytes!= null)
                   isBytes.close();
           }
           catch (IOException e)
           {
           }       
       }
       return oResponse;
   }
}
