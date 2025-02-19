/*
 * Copyright (c) 2009--2010 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package com.redhat.rhn.common.util.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.redhat.rhn.common.localization.LocalizationService;
import com.redhat.rhn.common.util.DynamicComparator;
import com.redhat.rhn.common.validator.test.TestObject;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.testing.RhnJmockBaseTestCase;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class DynamicComparatorTest extends RhnJmockBaseTestCase {

    @Test
    public void testComparatorMaps() {
        List list = generateRandomList();
        DynamicComparator comp = new DynamicComparator("stringField",
                RequestContext.SORT_ASC);
        list.sort(comp);
        assertEquals("A", ((TestObject) list.get(0)).getStringField());
        assertEquals("Z", ((TestObject) list.get(list.size() - 1)).getStringField());
    }

    public static List generateRandomList() {
        List retval = new LinkedList();
        List letters = LocalizationService.getInstance().getAlphabet();
        Collections.shuffle(letters);
        for (Object letterIn : letters) {
            TestObject to = new TestObject();
            to.setStringField((String) letterIn);
            retval.add(to);
        }
        return retval;
    }



}
