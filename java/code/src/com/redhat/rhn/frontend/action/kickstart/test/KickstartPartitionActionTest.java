/*
 * Copyright (c) 2009--2015 Red Hat, Inc.
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
package com.redhat.rhn.frontend.action.kickstart.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.redhat.rhn.domain.kickstart.KickstartData;
import com.redhat.rhn.domain.kickstart.test.KickstartDataTest;
import com.redhat.rhn.frontend.action.kickstart.KickstartPartitionEditAction;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.testing.RhnPostMockStrutsTestCase;
import com.redhat.rhn.testing.TestUtils;

import org.apache.struts.action.DynaActionForm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * KickstartPreActionTest
 */
public class KickstartPartitionActionTest extends RhnPostMockStrutsTestCase {
    private KickstartData ksdata;

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();

        this.ksdata = KickstartDataTest.createKickstartWithOptions(user.getOrg());
        TestUtils.saveAndFlush(ksdata);
        addRequestParameter(RequestContext.KICKSTART_ID, this.ksdata.getId().toString());
    }

    @Test
    public void testPopulatePartition() {
        setRequestPathInfo("/kickstart/KickstartPartitionEdit");
        addRequestParameter(RhnAction.SUBMITTED, Boolean.FALSE.toString());
        actionPerform();
        DynaActionForm form = (DynaActionForm) getActionForm();
        String formval = (String)form.get(KickstartPartitionEditAction.PARTITIONS);
        assertFalse(formval.isEmpty());
    }

    @Test
    public void testCleanSubmit() {

        String data = "part swap --size=1000 --grow --maxsize=3000\n" +
        "logvol swap --fstype swap --name=lvswap --vgname=Volume00 --size=2048\n" +
        "volgroup myvg --fstype swap --level 0 --device 1 raid.05 raid.06 raid.07 raid.08";
        setRequestPathInfo("/kickstart/KickstartPartitionEdit");
        addRequestParameter(KickstartPartitionEditAction.SUBMITTED,
                Boolean.TRUE.toString());
        addRequestParameter(KickstartPartitionEditAction.PARTITIONS, data);
        actionPerform();
        DynaActionForm form = (DynaActionForm) getActionForm();
        String formval = (String)form.get(KickstartPartitionEditAction.PARTITIONS);
        assertNotNull(formval);
        assertFalse(formval.isEmpty());
        assertEquals(data, formval);
        String[] keys = {"kickstart.partition.success",
                         "kickstart.software.changeencryption"};
        verifyActionMessages(keys);
        assertNotNull(ksdata.getPartitionData());
        assertEquals(data, ksdata.getPartitionData());

    }

    @Test
    public void testMultipleSwapsSubmit() {

        String data = "part swap --size=1000 --grow --maxsize=3000\n" +
        "partition swap --fstype swap --name=lvswap --vgname=Volume00 --size=2048\n" +
        "raid swap --fstype swap --level 0 --device 1 raid.05 raid.06 raid.07 raid.08";
        setRequestPathInfo("/kickstart/KickstartPartitionEdit");
        addRequestParameter(KickstartPartitionEditAction.SUBMITTED,
                Boolean.TRUE.toString());
        addRequestParameter(KickstartPartitionEditAction.PARTITIONS, data);
        actionPerform();
        DynaActionForm form = (DynaActionForm) getActionForm();
        String formval = (String)form.get(KickstartPartitionEditAction.PARTITIONS);

        assertFalse(formval.isEmpty());
        assertEquals(data, formval);
        assertNotNull(ksdata.getPartitionData());
        assertEquals(data, ksdata.getPartitionData());

        String[] keys = {"kickstart.partition.success",
                         "kickstart.software.changeencryption"};
        verifyActionMessages(keys);
    }

}


