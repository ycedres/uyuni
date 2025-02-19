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
package com.redhat.rhn.frontend.action.errata;

import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.dto.ErrataOverview;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.ListHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.Listable;
import com.redhat.rhn.manager.errata.ErrataManager;

import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Base action for all pages that display an errata list. Subclasses simply implement
 * the {@link #getErrataFilter()} method to indicate what data to return.
 *
 */
public abstract class ErrataListBaseAction extends RhnAction implements Listable {

    /**
     * Indicates the specific erratum returned by a particular subclass.
     *
     * @return cannot be <code>null</code>
     */
    protected abstract ErrataFilter getErrataFilter();

    /** {@inheritDoc} */
    @Override
    public ActionForward execute(ActionMapping actionMapping,
                                 ActionForm actionForm,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {
        request.setAttribute("displayCves", isSecurityAction());
        ListHelper helper = new ListHelper(this, request);
        helper.execute();

        return actionMapping.findForward(RhnHelper.DEFAULT_FORWARD);
    }

    /** {@inheritDoc} */
    @Override
    public List<? extends ErrataOverview> getResult(RequestContext context) {

        User user = context.getCurrentUser();
        DataResult<ErrataOverview> result;

        switch (getErrataFilter()) {
            case ALL:
                result = ErrataManager.allErrata(user);
                break;

            case RELEVANT:
                result = ErrataManager.relevantErrata(user);
                break;

            default:
                throw new IllegalStateException("Subclass did not return a valid errata " +
                    "filter");
        }

        return result;
    }

    /**
     * Method to distinguish security errata actions
     * @return whether it is an action of Security Errata
     */
    public boolean isSecurityAction() {
        return false;
    }

    /**
     * Used by subclasses to dictate the data that is displayed.
     */
    protected enum ErrataFilter {
        ALL, RELEVANT
    }
}
