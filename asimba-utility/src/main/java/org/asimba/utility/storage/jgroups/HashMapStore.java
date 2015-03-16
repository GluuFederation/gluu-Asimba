/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.asimba.utility.storage.jgroups;

import com.alfaariss.oa.OAException;

/**
 *
 * @author jan
 */
public interface HashMapStore <T> {
    T get() throws OAException;
}
