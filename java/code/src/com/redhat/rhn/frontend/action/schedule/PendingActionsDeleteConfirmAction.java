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
package com.redhat.rhn.frontend.action.schedule;

import com.redhat.rhn.common.localization.LocalizationService;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.ActionFactory;
import com.redhat.rhn.domain.rhnset.RhnSet;
import com.redhat.rhn.domain.rhnset.RhnSetElement;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.dto.ScheduledAction;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.frontend.struts.StrutsDelegate;
import com.redhat.rhn.frontend.taglibs.list.helper.ListRhnSetHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.Listable;
import com.redhat.rhn.manager.action.ActionManager;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.rhnset.RhnSetManager;
import com.redhat.rhn.taskomatic.TaskomaticApiException;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.ActionMessage;
import org.apache.struts.action.ActionMessages;

import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * PendingActionsConfirmAction
 */
public class PendingActionsDeleteConfirmAction extends RhnAction implements Listable {

    private static final Logger LOG =
            LogManager.getLogger(PendingActionsDeleteConfirmAction.class);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public ActionForward execute(ActionMapping mapping,
            ActionForm formIn,
            HttpServletRequest request,
            HttpServletResponse response) {

        ListRhnSetHelper helper = new ListRhnSetHelper(this, request, getSetDecl());
        helper.setWillClearSet(false);
        helper.execute();
        if (helper.isDispatched()) {
            return cancelActions(mapping, request);
        }

        return mapping.findForward(RhnHelper.DEFAULT_FORWARD);
    }

    /**
     * {@inheritDoc}
     */
    protected RhnSetDecl getSetDecl() {
        return RhnSetDecl.ACTIONS_PENDING;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public List<ScheduledAction> getResult(RequestContext context) {
        return ActionManager.pendingActionsInSet(context.getCurrentUser(), null,
                getSetDecl().getLabel());
    }

    private ActionForward cancelActions(ActionMapping mapping, HttpServletRequest request) {
        RequestContext requestContext = new RequestContext(request);
        StrutsDelegate strutsDelegate = getStrutsDelegate();

        User user = requestContext.getCurrentUser();
        RhnSet set = getSetDecl().get(user);

        List<Action> actionsToCancel = new LinkedList<>();

        for (RhnSetElement element : set.getElements()) {
            actionsToCancel.add(ActionFactory.lookupById(element.getElement()));
        }

        ActionMessages msgs = new ActionMessages();

        try {
            ActionManager.cancelActions(user, actionsToCancel);
            // If there was only one action cancelled, display the "action"
            // cancelled message, else display the "actions" archived message.
            if (set.size() == 1) {
                msgs.add(ActionMessages.GLOBAL_MESSAGE,
                        new ActionMessage("message.actionCancelled",
                                LocalizationService.getInstance()
                                        .formatNumber(set.size())));
            }
            else {
                msgs.add(ActionMessages.GLOBAL_MESSAGE,
                        new ActionMessage("message.actionsCancelled",
                                LocalizationService.getInstance()
                                        .formatNumber(set.size())));
            }
            strutsDelegate.saveMessages(request, msgs);
        }
        catch (TaskomaticApiException e) {
            LOG.error(e);
            createErrorMessage(request,
                    "message.actionCancelServerFailure.taskscheduler.down",
                    StringUtils.EMPTY);
        }

        set.clear();
        RhnSetManager.store(set);

        return mapping.findForward("success");
    }
}
