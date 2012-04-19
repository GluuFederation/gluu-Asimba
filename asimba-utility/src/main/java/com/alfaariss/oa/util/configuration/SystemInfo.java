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
package com.alfaariss.oa.util.configuration;

import java.io.Serializable;
import java.util.Properties;

/**
 * Java Bean containing all system properties of a OAS.
 * 
 * @author EVB
 * @author Alfa & Ariss
 * @since 1.0
 */
public class SystemInfo implements Serializable, Comparable<SystemInfo>
{
    /** serialVersionUID */
    private static final long serialVersionUID = -6365387902656306883L;
    
    private String name;
    
    private String oasName;
    private String oasVersion;
    
    private String wwwName;
    
    private String jvmName;
    private String jvmVersion;
    private String jvmVendor;
    private String jvmRuntime;
    
    private String osName;
    private String osVersion;
    private String osArchitecture;
    
    private int availableProcessors;
    private long freeMem;
    private long maxMem;
    private long totalMem;
    
    /**
     * Retrieve all system information from System properties, {@link Runtime}, 
     * and given class.
     * 
     * @param main Main class to extract package information.
     * @return All known server information.
     */
    public static SystemInfo getSystemInfo(Class main)
    {        
        SystemInfo pInfo = new SystemInfo();
        //System and OS information      
        Properties pSystem = System.getProperties();         
        pInfo.osName = (String)pSystem.get("os.name");
        pInfo.osVersion = (String)pSystem.get("os.version");
        pInfo.osArchitecture = (String)pSystem.get("os.arch");
        pInfo.jvmName = (String)pSystem.get("java.vm.name");
        pInfo.jvmVersion = (String)pSystem.get("java.vm.version");
        pInfo.jvmVendor = (String)pSystem.get("java.vm.vendor");
        pInfo.jvmRuntime = (String)pSystem.get("java.runtime.name");
       //Retrieve package info from main class
        Package p = main.getPackage();
        pInfo.oasName = p.getSpecificationTitle();
        pInfo.oasVersion = p.getSpecificationVersion();
        //Rutime info
        Runtime r = Runtime.getRuntime();
        pInfo.availableProcessors = r.availableProcessors();
        pInfo.maxMem = r.maxMemory();
        pInfo.freeMem = r.freeMemory();
        pInfo.totalMem = r.totalMemory();
        //TODO additional properties (e.g. uptime) (EVB)
        return pInfo;
    }
  
    /**
     * Retrieve the memory usage based on the class variables.
     * @return The memory usage.
     */
    public int getMemoryUsage()
    {  
        long used = totalMem - freeMem;
        //load
        double dLoad = (used >= 0 && totalMem > 0) 
            ? used * ((double)100 / (double)totalMem)
            : 0;
        
        return (int)dLoad;
      
    }
    
    /**
     * @return the availableProcessors
     */
    public int getAvailableProcessors()
    {
        return availableProcessors;
    }

    /**
     * @param availableProcessors the availableProcessors to set
     */
    public void setAvailableProcessors(int availableProcessors)
    {
        this.availableProcessors = availableProcessors;
    }

    /**
     * @return the freeMem
     */
    public long getFreeMem()
    {
        return freeMem;
    }

    /**
     * @param freeMem the freeMem to set
     */
    public void setFreeMem(long freeMem)
    {
        this.freeMem = freeMem;
    }

    /**
     * @return the jvmName
     */
    public String getJvmName()
    {
        return jvmName;
    }

    /**
     * @param jvmName the jvmName to set
     */
    public void setJvmName(String jvmName)
    {
        this.jvmName = jvmName;
    }

    /**
     * @return the jvmRuntime
     */
    public String getJvmRuntime()
    {
        return jvmRuntime;
    }

    /**
     * @param jvmRuntime the jvmRuntime to set
     */
    public void setJvmRuntime(String jvmRuntime)
    {
        this.jvmRuntime = jvmRuntime;
    }

    /**
     * @return the jvmVendor
     */
    public String getJvmVendor()
    {
        return jvmVendor;
    }

    /**
     * @param jvmVendor the jvmVendor to set
     */
    public void setJvmVendor(String jvmVendor)
    {
        this.jvmVendor = jvmVendor;
    }

    /**
     * @return the jvmVersion
     */
    public String getJvmVersion()
    {
        return jvmVersion;
    }

    /**
     * @param jvmVersion the jvmVersion to set
     */
    public void setJvmVersion(String jvmVersion)
    {
        this.jvmVersion = jvmVersion;
    }

    /**
     * @return the maxMem
     */
    public long getMaxMem()
    {
        return maxMem;
    }

    /**
     * @param maxMem the maxMem to set
     */
    public void setMaxMem(long maxMem)
    {
        this.maxMem = maxMem;
    }

    /**
     * @return the name
     */
    public String getName()
    {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name)
    {
        this.name = name;
    }

    /**
     * @return the oasName
     */
    public String getOasName()
    {
        return oasName;
    }

    /**
     * @param oasName the oasName to set
     */
    public void setOasName(String oasName)
    {
        this.oasName = oasName;
    }

    /**
     * @return the oasVersion
     */
    public String getOasVersion()
    {
        return oasVersion;
    }

    /**
     * @param oasVersion the oasVersion to set
     */
    public void setOasVersion(String oasVersion)
    {
        this.oasVersion = oasVersion;
    }

    /**
     * @return the osArchitecture
     */
    public String getOsArchitecture()
    {
        return osArchitecture;
    }

    /**
     * @param osArchitecture the osArchitecture to set
     */
    public void setOsArchitecture(String osArchitecture)
    {
        this.osArchitecture = osArchitecture;
    }

    /**
     * @return the osName
     */
    public String getOsName()
    {
        return osName;
    }

    /**
     * @param osName the osName to set
     */
    public void setOsName(String osName)
    {
        this.osName = osName;
    }

    /**
     * @return the osVersion
     */
    public String getOsVersion()
    {
        return osVersion;
    }

    /**
     * @param osVersion the osVersion to set
     */
    public void setOsVersion(String osVersion)
    {
        this.osVersion = osVersion;
    }

    /**
     * @return the totalMem
     */
    public long getTotalMem()
    {
        return totalMem;
    }

    /**
     * @param totalMem the totalMem to set
     */
    public void setTotalMem(long totalMem)
    {
        this.totalMem = totalMem;
    }

    /**
     * @return the wwwName
     */
    public String getWwwName()
    {
        return wwwName;
    }

    /**
     * @param wwwName the wwwName to set
     */
    public void setWwwName(String wwwName)
    {
        this.wwwName = wwwName;
    }

    /**
     * Compare names.
     * @param o The other.
     * @return  the value <code>0</code> if the other name is equal to
     *          this name; a value less than <code>0</code> if this name
     *          is lexicographically less than the other name; and a
     *          value greater than <code>0</code> if this name is
     *          lexicographically greater than the other name.
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    public int compareTo(SystemInfo o)
    {
        return name != null ? name.compareTo(o.name) : 0;
    }
    
}
