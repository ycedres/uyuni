/*
 * Copyright (c) 2009--2014 Red Hat, Inc.
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
package com.redhat.rhn.frontend.action.ssm;

import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.manager.ssm.SsmOperationManager;

import java.util.List;

public class ViewCompletedLogAction extends BaseViewLogAction {

    /** {@inheritDoc} */
    @Override
    public List getResult(RequestContext context) {
        User user = context.getCurrentUser();
        return SsmOperationManager.completedOperations(user);
    }

    @Override
    protected String getSummaryKey() {
        return "ssm.operations.completed.summary";
    }
}
