/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.util;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.util.resource.HttpResource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.w3c.dom.Document;

/**
 * Retrieves a remote IDP list to be used for proxy attribute 'GetComplete'.
 *
 * @author jre
 * @author Alfa & Ariss
 * @since 1.0
 */
public class RemoteIDPListEntry extends HttpResource
{
    private ParserPool _ppool = null;
    private HttpClient _client = null;
    private IDPList _list = null;
    private Log _logger = null;

    /**
     * Constructor
     *
     * @param resource The URI where the list can be found.
     * @param timeOutMillis The time out in milliseconds.
     */
    public RemoteIDPListEntry (String resource, int timeOutMillis)
    {
        super(resource);
        _logger = LogFactory.getLog(RemoteIDPListEntry.class);
        _ppool = new BasicParserPool();
        
        HttpClientParams clientParams = new HttpClientParams();
        clientParams.setSoTimeout(timeOutMillis);
        _client = new HttpClient(clientParams);
    }

    /**
     * Retrieves the list.
     * 
     * @return The IDPList xml resource.
     * @throws ResourceException When list could not be fetched or is malformed.
     */
    public IDPList getList() throws ResourceException
    {
        if (getLastModifiedTime().compareTo(new DateTime()) < 0 && _list != null)
        {
            //not modified lately
            _logger.debug("Resource not modified lately");
            return _list;
        }
        
        _logger.debug("Retrieving resource from URL " + getLocation());
        
        GetMethod m = super.getResource();
        
        try
        {
            _client.executeMethod(m);
            if (m.getStatusCode() == HttpStatus.SC_OK)
            {
                _list = unmarshall(m.getResponseBodyAsStream());
                _logger.debug("Resource successfully retrieved from URL " + getLocation());
                return _list;
            }
            
            StringBuffer buf = new StringBuffer("Retrieval of IDPList returned wrong HTTP status: ");
            buf.append(m.getStatusCode());
            throw new ResourceException(buf.toString());
        }
        catch (HttpException e)
        {
            throw new ResourceException("HTTP Error occurred", e);
        }
        catch (IOException e)
        {
            throw new ResourceException("I/O error occurred", e);
        }
    }
    
    private IDPList unmarshall(InputStream strm)
    throws ResourceException
    {
        UnmarshallerFactory unmarshallerFactory =
            Configuration.getUnmarshallerFactory();
        
        try
        {
            Document doc = _ppool.parse(strm);

            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(doc.getDocumentElement());
            XMLObject idpList = unmarshaller.unmarshall(doc.getDocumentElement());
            
            if (idpList instanceof IDPList)
            {
                return (IDPList)idpList;
            }
            
            throw new ResourceException("XML Object successfully loaded, but not of type IDPList.");
        }
        catch(XMLParserException pe)
        {
            throw new ResourceException("Remote resource could not be parsed", pe);
        }
        catch (UnmarshallingException e)
        {
            throw new ResourceException("Remote resource could not be unmarshalled", e);
        }
    }
}
