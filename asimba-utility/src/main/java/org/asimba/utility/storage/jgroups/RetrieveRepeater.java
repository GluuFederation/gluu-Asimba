/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.asimba.utility.storage.jgroups;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import org.apache.commons.logging.Log;

/**
 *
 * @author jan
 */
public class RetrieveRepeater <T> {
    private int repeats;
    private long sleep;
    private long invocations;
    private long[] repetitions;
    private long failures;

    public RetrieveRepeater(int repeats, long sleep) {
        this.repeats = repeats;
        this.sleep = sleep;
        this.invocations = 0;
        this.failures = 0;
        this.repetitions = new long[repeats + 1];
    }


    public T get(HashMapStore<T> store) throws OAException {
        T result = null;
        try {
            result = repeat(store);
        }
        catch (Exception e) {
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        
        return result;
    }

    
    private T repeat(HashMapStore<T> store) throws Exception {
        if (repeats <= 0) {
            return store.get();
        }
        int cycle = 0;
        T result;

        invocations++;
        while ((result = store.get()) == null && cycle < this.repeats) {
            Thread.sleep(cycle * this.sleep);
            this.repetitions[cycle] += 1;
            ++cycle;
        }

        if (result == null) {
            ++failures;
        }

        return result;
    }

    public void logReport(Log logger) {
        logger.info("");
        logger.info(RetrieveRepeater.class.toString());
        logger.info("Invocations: " + invocations);
        logger.info("Successes per cycle (0 means direct succes):");
        for (int i = 0; i < repetitions.length; ++i) {
            logger.info("  " + i + " after " + (i * sleep) + " msecs: " + repetitions[i]);
        }
        logger.info("Failures: " + failures);
        logger.info("");
    }
    
    public long[] getRepetitions() {
        return repetitions;
    }
}