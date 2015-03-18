/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.asimba.utility.storage.jgroups;

import com.alfaariss.oa.OAException;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import org.junit.Test;

/**
 *
 * @author jan
 */
public class RetrieveRepeaterTest {
    private static final Log log = LogFactory.getLog(RetrieveRepeaterTest.class);

    @Test
    public void testRepeatsWithNotFound() throws Exception {
        final int REPEATS = 5;
        final long SLEEP = 5;

        RetrieveRepeater<String> rr = new RetrieveRepeater<>(REPEATS, SLEEP);
        rr.setFailureLogging(true, RetrieveRepeaterTest.class.getName());
        checkCycles(rr, -1);
        String result = rr.get(new HashMapStore<String>() {
            @Override
            public String get() throws OAException {
                return null;
            }
        });
        assertThat(result, equalTo(null));
        checkCycles(rr, REPEATS);
    }
    
    @Test
    public void testRepeatsWithImmediateSuccess() throws Exception {
        final int REPEATS = 5;
        final long SLEEP = 5;

        RetrieveRepeater<String> rr = new RetrieveRepeater<>(REPEATS, SLEEP);
        rr.setFailureLogging(true, RetrieveRepeaterTest.class.getName());
        checkCycles(rr, -1);
        String result = rr.get(new HashMapStore<String>() {
            @Override
            public String get() throws OAException {
                return "success";
            }
        });
        assertThat(result, not(equalTo(null)));
        checkCycles(rr, 0);
    }
    
    private class DelayedStore implements HashMapStore {
        private int invocations = 0;
        private int delay;
        
        public DelayedStore(int delay) {
            this.delay = delay;
        }

        @Override
        public String get() throws OAException {
            if (invocations++ < delay) {
                return null;
            }
            return "success";
        }
    }
    
    @Test
    public void testRepeatsWithDelayedSuccess() throws Exception {
        final int REPEATS = 10;
        final long SLEEP = 5;
        final int DELAY = 7;

        RetrieveRepeater<String> rr = new RetrieveRepeater<>(REPEATS, SLEEP);
        rr.setFailureLogging(true, RetrieveRepeaterTest.class.getName());
        checkCycles(rr, -1);
        
        long start = System.currentTimeMillis();
        String result = rr.get(new DelayedStore(DELAY));
        long stop = System.currentTimeMillis();
        
        assertThat(result, not(equalTo(null)));
        checkCycles(rr, DELAY);
        assertTrue("Some time is expected to have passed (" + (stop - start) + " > " + expectedDelay(SLEEP, DELAY) + ")", stop - start >= expectedDelay(SLEEP, DELAY));
    }

    
    public void checkCycles(RetrieveRepeater rr, int expectedSuccessIndex) {
        long[] repeats = rr.getRepetitions();
        for (int i = 0; i < repeats.length; ++i) {
            if (i < expectedSuccessIndex) {
                assertThat("repeats[" + i + "] should be 1", repeats[i], equalTo(1l));
            }
            else {
                assertThat("repeats[" + i + "] should be 0", repeats[i], equalTo(0l));
            }
        }
    }

    public long expectedDelay(long sleep, int repeats) {
        long delay = 0;
        for (int i = 0; i < repeats; ++i) {
            delay += i * sleep;
        }
        return delay;
    }
}
