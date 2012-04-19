/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.util.configuration;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.configuration.handler.IConfigurationHandler;

/**
 * A common configuration manager.
 * 
 * The <code>ConfigurationManager</code> offers an interface to the 
 * configuration, which can be used by all OA components. 
 * 
 * It's set up like a factory to resolve the right 
 * <code>IConfigurationHandler</code> to read and write the configuration 
 * from several sources.
 * 
 * <br><br><i>Partitially based on sources from A-Select (www.a-select.org).</i>
 *
 * @author MHO
 * @author Alfa & Ariss
 * @author EVB 
 */
public class ConfigurationManager implements IConfigurationManager
{
    /** system logger */
    private Log _logger;
    private IConfigurationHandler _oConfigHandler;
    private Document _oDomDocument;

	/**
	 * Default constructor. 
	 */
	public ConfigurationManager()
    {
	    _logger = LogFactory.getLog(ConfigurationManager.class);
        _oConfigHandler = null;
        _oDomDocument = null;
	}
    
	/**
	 * Initialize the <code>ConfigurationManager</code>.
	 * @see IConfigurationManager#init(IConfigurationHandler)
	 */
	public synchronized void init(IConfigurationHandler _handler)
	  throws ConfigurationException
    {
        try
        {
            _oConfigHandler = _handler;
            _oDomDocument = _oConfigHandler.parseConfiguration();
        }
        catch (ConfigurationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error", e);
            throw new ConfigurationException(SystemErrors.ERROR_INTERNAL);
        }
	}   
    
	/**
	 * Saves the configuration.
	 * @see IConfigurationManager#saveConfiguration()
	 */
	public synchronized void saveConfiguration() throws ConfigurationException
    {
        boolean bFound = false;
        Date dNow = null;
        StringBuffer sbComment = null;
        Element elRoot = null;
        Node nCurrent = null;
        Node nComment = null;
        String sValue = null;
        try
        {
            // add date to configuration
            dNow = new Date(System.currentTimeMillis());

            sbComment = new StringBuffer(" Configuration changes saved on ");
            sbComment.append(DateFormat.getDateInstance().format(dNow));
            sbComment.append(". ");

            elRoot = _oDomDocument.getDocumentElement();
            nCurrent = elRoot.getFirstChild();
            while (!bFound && nCurrent != null) // all elements
            {
                if (nCurrent.getNodeType() == Node.COMMENT_NODE)
                {
                    // check if it's a "save changes" comment
                    sValue = nCurrent.getNodeValue();
                    if (sValue.trim().startsWith(
                        "Configuration changes saved on"))
                    {
                        // overwrite message
                        nCurrent.setNodeValue(sbComment.toString());
                        bFound = true;
                    }
                }
                nCurrent = nCurrent.getNextSibling();
            }
            if (!bFound) // no comment found: adding new
            {
                // create new comment node
                nComment = _oDomDocument.createComment(sbComment.toString());
                // insert comment before first node
                elRoot.insertBefore(nComment, elRoot.getFirstChild());
            }
            _oConfigHandler.saveConfiguration(_oDomDocument);
        }
        catch (ConfigurationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error", e);
            throw new ConfigurationException(SystemErrors.ERROR_INTERNAL);
        }
    }
  
	/**
	 * Retrieves a config section by its type and id.
	 * @see IConfigurationManager#getSection(org.w3c.dom.Element, java.lang.String, java.lang.String)
	 */
	public synchronized Element getSection(Element eRootSection, 
        String sSectionType, String sSectionID)
	  
    {
        if(sSectionID == null) 
            throw new IllegalArgumentException("Suplied section ID is empty");
        if(sSectionType == null) 
            throw new IllegalArgumentException("Suplied section type is empty");
               //rootSection may be null if the first section is requested
        if (eRootSection == null)
            eRootSection = _oDomDocument.getDocumentElement();        
        return getSubSectionByID(eRootSection, sSectionType, sSectionID);
	}
   
	/**
	 * Retrieves a config section by its type.
	 * @see IConfigurationManager#getSection(org.w3c.dom.Element, java.lang.String)
	 */
	public synchronized Element getSection(Element eRootSection, String sSectionType)
    {
        if(sSectionType == null) 
            throw new IllegalArgumentException("Suplied section type is empty");
        //rootSection can be null if the first section is requested
        if (eRootSection == null)
            eRootSection = _oDomDocument.getDocumentElement();        
        return getSubSection(eRootSection, sSectionType);
	}

	/**
	 * Creates a new configuration section (empty tag) with section 
     * type as its name.
	 * @see IConfigurationManager#createSection(java.lang.String)
	 */
	public synchronized Element createSection(String sSectionType)
	  throws ConfigurationException
    {
        if(sSectionType == null) 
            throw new IllegalArgumentException("Suplied section type is empty");
        Element eRet = null;       
        try
        {
            eRet = _oDomDocument.createElement(sSectionType);
        }
        catch(DOMException e)
        {
            _logger.error("Could not create section: " + sSectionType, e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
        }
        return eRet;
	}

	
	/**
	 * Add a new configuration section to the configuration.
	 * @see IConfigurationManager#setSection(org.w3c.dom.Element, org.w3c.dom.Element)
	 */
	public synchronized void setSection(
        Element eRootSection, Element eNewSection) throws ConfigurationException
    {
        if(eNewSection == null) 
            throw new IllegalArgumentException("Suplied section is empty");
        
        //rootSection can be null if the first section is requested
        if (eRootSection == null)
            eRootSection = _oDomDocument.getDocumentElement();
    
        try
        {
            eRootSection.appendChild(eNewSection);
        }
        catch (DOMException e)
        {
            _logger.error("Could not add section: " +  
                eNewSection.getNodeName(), e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
        }
	}
	    
	/**
	 * Retrieve a configuration parameter value.
	 *
	 * Retrieves the value of the config parameter from the config section 
     * that is supplied.
	 * @param eSection The base section.
	 * @param sName The parameter name.
	 * @return The paramater value.
	 * @throws ConfigurationException If retrieving fails.
	 */
	public synchronized String getParam(Element eSection, String sName)
	  throws ConfigurationException
    {
        if(eSection == null) 
            throw new IllegalArgumentException("Suplied section is empty");
        if(sName == null) 
            throw new IllegalArgumentException("Suplied name is empty");
    
        String sValue = null;
        try
        {
            //check attributes within the section tag
            if (eSection.hasAttributes())
            {
                NamedNodeMap oNodeMap = eSection.getAttributes();
                Node nAttribute = oNodeMap.getNamedItem(sName);
                if (nAttribute != null)
                    sValue = nAttribute.getNodeValue();
            }
            
            if (sValue == null)
            {//check sub sections
                NodeList nlChilds = eSection.getChildNodes();
                for (int i = 0; i < nlChilds.getLength(); i++)
                {
                    Node nTemp = nlChilds.item(i);
                    if (nTemp != null
                        && nTemp.getNodeName().equalsIgnoreCase(sName))
                    {
                        NodeList nlSubNodes = nTemp.getChildNodes();
                        if (nlSubNodes.getLength() > 0)
                        {
                            for (int iSub = 0; iSub < nlSubNodes.getLength(); iSub++)
                            {
                                Node nSubTemp = nlSubNodes.item(iSub);
                                if (nSubTemp.getNodeType() == Node.TEXT_NODE)
                                {
                                    sValue = nSubTemp.getNodeValue();
                                    if (sValue == null)
                                        sValue = "";
                                    
                                    return sValue;
                                }
                            }
                        }
                        else
                        {
                            if (sValue == null)
                                sValue = "";
                            
                            return sValue;
                        }
                    }
                }
            }
        }
        catch (DOMException e)
        {
            _logger.error("Could not retrieve parameter: " + sValue, e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
        }
        return sValue;
	}
	
	/**
	 * Set a configuration parameter value.
	 * @see IConfigurationManager#setParam(org.w3c.dom.Element, java.lang.String, java.lang.String, boolean)
	 */
	public synchronized void setParam(Element eSection, String sName, 
        String sValue, boolean bMandatory) throws ConfigurationException
    {
        if(eSection == null) 
            throw new IllegalArgumentException("Suplied section is empty");
        if(sName == null) 
            throw new IllegalArgumentException("Suplied name is empty");     
        if(sValue == null)
            throw new IllegalArgumentException("Suplied value is empty");
        try
        {
            if (bMandatory)
                eSection.setAttribute(sName, sValue);//set as attribute in tag
            else
                setParamAsChild(eSection, sName, sValue);//set as child tag
        }
        catch (DOMException e)
        {
            _logger.error("Could not set parameter: " + sName, e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
        }
	}
	
	/**
	 * @see com.alfaariss.oa.api.configuration.IConfigurationManager#getParams(org.w3c.dom.Element, java.lang.String)
	 */
	public synchronized List<String> getParams(Element eSection, String sParamName) 
	    throws ConfigurationException
	{
	    if(eSection == null) 
            throw new IllegalArgumentException("Suplied section is empty");
        if(sParamName == null) 
            throw new IllegalArgumentException("Suplied parameter name is empty");
    
        
        List<String> listValues = new Vector<String>();
        
        try
        {
            //check attributes within the section tag
            if (eSection.hasAttributes())
            {
                NamedNodeMap oNodeMap = eSection.getAttributes();
                Node nAttribute = oNodeMap.getNamedItem(sParamName);
                if (nAttribute != null)
                {
                    String sAttributeValue = nAttribute.getNodeValue();
                    if (sAttributeValue != null)
                        listValues.add(sAttributeValue);
                }
            }
            
            NodeList nlChilds = eSection.getChildNodes();
            for (int i = 0; i < nlChilds.getLength(); i++)
            {
                Node nTemp = nlChilds.item(i);
                if (nTemp != null
                    && nTemp.getNodeName().equalsIgnoreCase(sParamName))
                {
                    String sValue = "";
                    NodeList nlSubNodes = nTemp.getChildNodes();
                    if (nlSubNodes.getLength() > 0)
                    {
                        for (int iSub = 0; iSub < nlSubNodes.getLength(); iSub++)
                        {
                            Node nSubTemp = nlSubNodes.item(iSub);
                            if (nSubTemp.getNodeType() == Node.TEXT_NODE)
                            {
                                sValue = nSubTemp.getNodeValue();
                                if (sValue == null)
                                    sValue = "";
                            }
                        }
                    }
                    
                    listValues.add(sValue);
                }
            }
            
            if (listValues.isEmpty())
                return null;
        }
        catch (DOMException e)
        {
            _logger.error("Could not retrieve parameter: " + sParamName, e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
        }
        
	    return listValues;
	}
    
	/**
	 * Resolve the next section.
	 * @see IConfigurationManager#getNextSection(org.w3c.dom.Element)
	 */
	public synchronized Element getNextSection(Element eSection)
    {
        if(eSection == null) 
            throw new IllegalArgumentException("Suplied section is empty");
        
        String sRequested = eSection.getNodeName();
        //Get first
        Node nNext = eSection.getNextSibling();
        while (nNext != null) //No more sections
        {
            if (nNext.getNodeType() == Node.ELEMENT_NODE && 
                nNext.getNodeName().equals(sRequested))
                break;
            nNext = nNext.getNextSibling(); //Get next
        }
        return (Element)nNext;
	}
   
	/**
	 * Remove a configuration section.
	 * @see IConfigurationManager#removeSection(org.w3c.dom.Element, java.lang.String)
	 */
	public synchronized boolean removeSection(
        Element eRootSection, String sName) throws ConfigurationException
    {
        if(sName == null) 
            throw new IllegalArgumentException("Suplied name is empty");

        boolean bRet = false;
        try
        {
            //rootSection can be null if the first section is requested
            if (eRootSection == null)
                eRootSection = _oDomDocument.getDocumentElement();
    
            Node nSection = getSubSection(eRootSection, sName);
            if (nSection == null)
                _logger.debug("Section not found: " + sName);
            else
            {
                //remove section
                eRootSection.removeChild(nSection);
                bRet = true;
            }   
        }
        catch (DOMException e)
        {
            _logger.error("Error removing section: " + sName,e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_DELETE);
        }
        return bRet;
	}
    
	/**
	 * Remove a configuration section.
	 * @see IConfigurationManager#removeSection(org.w3c.dom.Element, java.lang.String, java.lang.String)
	 */
	public synchronized boolean removeSection(Element eRootSection, 
        String sName, String sSectionID) throws ConfigurationException
    {
        if(sName == null) 
            throw new IllegalArgumentException("Suplied name is empty");
        if(sSectionID == null) 
            throw new IllegalArgumentException("Suplied section id is empty");
        boolean bRet = false;
    
        try
        {
            if (eRootSection == null)
                eRootSection = _oDomDocument.getDocumentElement();
    
            Node nSection = this.getSubSectionByID(eRootSection, sName, sSectionID);
            if (nSection == null)
                _logger.debug("Section not found: " + sName);
            else
            {
                //remove section
                eRootSection.removeChild(nSection);
                bRet = true;
            }   
        }
        catch (DOMException e)
        {
            StringBuffer sb = new StringBuffer("Error removing section: ");
            sb.append(sName).append(", id=").append(sSectionID);
            _logger.error(sb.toString(),e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_DELETE);
        }
        return bRet;
	}

	//Adds a parameter to the given section.
	private void setParamAsChild(Element eSection, String sName, String sValue)
	  throws DOMException
    {
        boolean bFound = false;
    
        //check if child allready exists
        NodeList nlChilds = eSection.getChildNodes();
        for (int i = 0; i < nlChilds.getLength(); i++)
        {
            Node nTemp = nlChilds.item(i);
            //check if tagname = configItem
            if (nTemp != null
                && nTemp.getNodeName().equalsIgnoreCase(sName))
            {
                NodeList nlSubNodes = nTemp.getChildNodes();
                for (int iIter2 = 0; iIter2 < nlSubNodes.getLength(); iIter2++)
                {
                    Node nSubTemp = nlSubNodes.item(iIter2);
                    if (nSubTemp.getNodeType() == Node.TEXT_NODE)
                    {
                        nSubTemp.setNodeValue(sValue);
                        bFound = true;
                    }
                }
            }
        }
    
        if (!bFound) //add new child
        {
            //create new child
            Node nValue = _oDomDocument.createTextNode(sValue);
            Element nConfigItem = _oDomDocument.createElement(sName);
            nConfigItem.appendChild(nValue);
    
            //append child
            eSection.appendChild(nConfigItem);
        }
	}

	//Retrieve an XML tag with given <code>sSectionID</code> as an attribute.
	private synchronized Element getSubSectionByID(Element eRootSection, String sSectionType, String sSectionID)
    {
        assert eRootSection != null : "Suplied root section is empty";
        //split sectionID (id=ticket) to key/value pair
    
        int iFirstEquals = sSectionID.indexOf("=");
        if (iFirstEquals == -1)
        {
            StringBuffer sbError = new StringBuffer(
                "Invalid section ID (must contain a '='): ");
            sbError.append(sSectionID);
            _logger.debug(sbError.toString());    
            throw new IllegalArgumentException("Invalid section ID (should be name=value)");
        }
    
        String sKey = sSectionID.substring(0, iFirstEquals);
        String sValue = sSectionID.substring(iFirstEquals + 1, sSectionID.length());
    
        //get all childnodes
        NodeList nlChilds = eRootSection.getChildNodes();
        for (int i = 0; i < nlChilds.getLength(); i++)
        {
            Node nCurrent = nlChilds.item(i);
            //white spaces not supported, so only element_node
            if (nCurrent.getNodeType() == Node.ELEMENT_NODE)
            {
                Element eCurrent = (Element)nCurrent;
                if (eCurrent.getNodeName().equalsIgnoreCase(sSectionType)
                    && eCurrent.hasAttributes())
                {
                    //check if node has the strKey attribute and check if
                    // its value = strvalue
                    if (eCurrent.getAttribute(sKey).equalsIgnoreCase(sValue))
                        return eCurrent;
                }
            }
        }
    
        return null;
	}

	//Retrieve an XML tag of the given type.
	private synchronized Element getSubSection(Element eRootSection, String sSectionType)
    {
        assert eRootSection != null : "Suplied root section is empty";
        
        if (eRootSection.hasChildNodes())
        {
            Node nTemp = eRootSection.getFirstChild();
            while (nTemp != null)
            {
                if (nTemp.getNodeType() == Node.ELEMENT_NODE
                    && nTemp.getNodeName().equals(sSectionType))
                {
                    return (Element)nTemp;
                }
                nTemp = nTemp.getNextSibling();
            }
        }
        return null;
	}

}