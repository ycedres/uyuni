/*
 * Copyright (c) 2013--2014 Red Hat, Inc.
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
package com.redhat.rhn.frontend.action.systems.duplicate;

import com.redhat.rhn.common.messaging.MessageQueue;
import com.redhat.rhn.domain.rhnset.RhnSet;
import com.redhat.rhn.frontend.events.SsmDeleteServersEvent;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.ListHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.Listable;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.rhnset.RhnSetManager;
import com.redhat.rhn.manager.system.SystemManager;

import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * DuplicateSystemsDeleteSetupAction
 */
public class DuplicateSystemsDeleteSetupAction extends RhnAction implements Listable {
    /**
    * {@inheritDoc}
    */
    @Override
    public ActionForward execute(ActionMapping mapping,
                                 ActionForm formIn,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {
       RequestContext context = new RequestContext(request);
       if (context.wasDispatched("ssm.delete.systems.confirmbutton")) {
           return handleConfirm(context, mapping);
       }

       ListHelper helper = new ListHelper(this, request);
       helper.execute();

       boolean saltMinionsPresent = SystemManager.containsSaltMinion(helper.getDataSet());
       request.setAttribute("saltMinionsPresent", saltMinionsPresent);

       return mapping.findForward(RhnHelper.DEFAULT_FORWARD);
    }

    private ActionForward handleConfirm(RequestContext context,
            ActionMapping mapping) {

        RhnSet set = RhnSetDecl.DUPLICATE_SYSTEMS.get(context.getCurrentUser());
        String saltCleanup = context.getRequiredParamAsString("saltCleanup");
        // Fire the request off asynchronously
        SsmDeleteServersEvent event =
            new SsmDeleteServersEvent(context.getCurrentUser(),
                    new ArrayList<>(set.getElementValues()),
                    SystemManager.ServerCleanupType
                            .fromString(saltCleanup)
                            .orElseThrow(() ->
                                    new IllegalArgumentException(
                                            "Invalid server cleanup type value: " +
                                                    saltCleanup))
                    );
        MessageQueue.publish(event);
        set.clear();
        RhnSetManager.store(set);

        getStrutsDelegate().saveMessage("duplicate.systems.delete.confirmmessage",
                                                    context.getRequest());
        return mapping.findForward(RhnHelper.CONFIRM_FORWARD);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List getResult(RequestContext contextIn) {
        return SystemManager.inSet(contextIn.getCurrentUser(),
                RhnSetDecl.DUPLICATE_SYSTEMS.getLabel(), true);
    }
}
