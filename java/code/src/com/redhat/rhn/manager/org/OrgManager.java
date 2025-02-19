/*
 * Copyright (c) 2009--2017 Red Hat, Inc.
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
package com.redhat.rhn.manager.org;

import static com.redhat.rhn.domain.role.RoleFactory.ORG_ADMIN;

import com.redhat.rhn.common.db.datasource.DataList;
import com.redhat.rhn.common.db.datasource.ModeFactory;
import com.redhat.rhn.common.db.datasource.SelectMode;
import com.redhat.rhn.common.localization.LocalizationService;
import com.redhat.rhn.common.security.PermissionException;
import com.redhat.rhn.common.validator.ValidatorException;
import com.redhat.rhn.domain.channel.ChannelFamily;
import com.redhat.rhn.domain.channel.ChannelFamilyFactory;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.org.OrgFactory;
import com.redhat.rhn.domain.role.Role;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.dto.MultiOrgUserOverview;
import com.redhat.rhn.frontend.dto.OrgChannelDto;
import com.redhat.rhn.frontend.dto.OrgDto;
import com.redhat.rhn.frontend.dto.OrgTrustOverview;
import com.redhat.rhn.frontend.dto.TrustedOrgDto;
import com.redhat.rhn.manager.BaseManager;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OrgManager - Manages MultiOrg tasks
 */
public class OrgManager extends BaseManager {

    private static final String ORG_LIST = "org list";

    private OrgManager() {
    }


    /**
     * Basically transfers relevant data
     * from Org object to the Dto object
     * returns a new OrgDto object.
     * This method is typically used in OrgDetails views
     * @param org the org object to transfer from
     * @return the created Dto.
     */
    public static OrgDto toDetailsDto(Org org) {
        OrgDto dto = new OrgDto();
        dto.setId(org.getId());
        dto.setName(org.getName());
        dto.setUsers(OrgFactory.getActiveUsers(org));
        dto.setSystems(OrgFactory.getActiveSystems(org));
        dto.setActivationKeys(OrgFactory.getActivationKeys(org));
        dto.setKickstartProfiles(OrgFactory.getKickstarts(org));
        dto.setServerGroups(OrgFactory.getServerGroups(org));
        dto.setConfigChannels(OrgFactory.getConfigChannels(org));
        dto.setStagingContentEnabled(org.getOrgConfig().isStagingContentEnabled());
        return dto;
    }


    /**
     *
     * @param user User to cross security check
     * @return List of Orgs on satellite
     */
    public static DataList<OrgDto> activeOrgs(User user) {
        if (!user.hasRole(RoleFactory.SAT_ADMIN)) {
            throw getNoAdminError(RoleFactory.SAT_ADMIN, ORG_LIST);
        }
        SelectMode m = ModeFactory.getMode("Org_queries", "orgs_in_satellite");

        return DataList.getDataList(m, Collections.emptyMap(),
                Collections.emptyMap());
    }

    private static PermissionException getNoAdminError(Role role, String list) {
        // Throw an exception w/error msg so the user knows what went wrong.
        LocalizationService ls = LocalizationService.getInstance();
        return new PermissionException("User must be a " + role.getName() + " to access the " + list,
                ls.getMessage("permission.jsp.title.orglist"),
                ls.getMessage("permission.jsp.summary.general"));
    }

    /**
     *
     * @param user User to cross security check
     * @return List of Orgs on satellite
     */
    public static DataList<TrustedOrgDto> trustedOrgs(User user) {
        if (!user.hasRole(RoleFactory.ORG_ADMIN)) {
            throw getNoAdminError(ORG_ADMIN, "trusted org list");
        }
        SelectMode m = ModeFactory.getMode("Org_queries", "trusted_orgs");

        Long orgIdIn = user.getOrg().getId();
        Map<String, Object> params = new HashMap<>();
        params.put("org_id", orgIdIn);

        return DataList.getDataList(m, params,
                Collections.emptyMap());
    }

    /**
     * Get a list of orgs with a trusted indicator for each.
     * @param user The user making the request.
     * @param orgIdIn The org to check.
     * @return A list of orgs with a trusted indicator for each.
     */
    @SuppressWarnings("unchecked")
    public static DataList<OrgTrustOverview> orgTrusts(User user, Long orgIdIn) {
        if (!user.hasRole(RoleFactory.SAT_ADMIN)) {
            throw getNoAdminError(RoleFactory.SAT_ADMIN, "trusted org list");
        }
        SelectMode m = ModeFactory.getMode("Org_queries", "trust_overview");
        Map<String, Object> params = new HashMap<>();
        params.put("org_id", orgIdIn);
        return DataList.getDataList(m, params, Collections.emptyMap());
    }

    /**
     *
     * @param orgIdIn to check active users
     * @return DataList of UserOverview Objects
     */
    public static DataList<MultiOrgUserOverview> activeUsers(Long orgIdIn) {
        SelectMode m = ModeFactory.getMode("User_queries", "users_in_multiorg");
        Map<String, Object> params = new HashMap<>();
        params.put("org_id", orgIdIn);
        return DataList.getDataList(m, params, Collections.emptyMap());
    }

    /**
     *
     * @param cid Channel ID
     * @param org Org used to check trust relationships
     * @return list of trusted relationships with access to cid
     */
    public static DataList<OrgChannelDto> orgChannelTrusts(Long cid, Org org) {
        SelectMode m = ModeFactory.getMode("Channel_queries",
                "protected_trust_channel");
        Map<String, Object> params = new HashMap<>();
        params.put("org_id", org.getId());
        params.put("cid", cid);
        return DataList.getDataList(m, params, Collections.emptyMap());
    }

    /**
     *
     * @return all users on sat
     */
    public static DataList allUsers() {
        SelectMode m = ModeFactory.getMode("User_queries",
                "all_users_in_multiorg");
        return DataList.getDataList(m, Collections.emptyMap(),
                Collections.emptyMap());
    }

    /**
     * Returns the total number of orgs on this satellite.
     * @param user User performing the query.
     * @return Total number of orgs.
     */
    public static Long getTotalOrgCount(User user) {
        if (!user.hasRole(RoleFactory.SAT_ADMIN)) {
            throw getNoAdminError(RoleFactory.SAT_ADMIN, ORG_LIST);
        }

        return OrgFactory.getTotalOrgCount();
    }

    /**
     * Returns the date which this org trusted the supplied orgId
     * @param user currently logged in user
     * @param org our org
     * @param trustOrg the org we trust
     * @return date we started trusting this org
     */
    public static Date getTrustedSince(User user, Org org, Org trustOrg) {
        if (!user.hasRole(RoleFactory.ORG_ADMIN)) {
            throw getNoAdminError(RoleFactory.ORG_ADMIN, "trusted since data");
        }

        return OrgFactory.getTrustedSince(org.getId(), trustOrg.getId());
    }

    /**
     * Returns the date which this org trusted the supplied orgId
     * @param user currently logged in user
     * @param org our org
     * @param trustOrg the org we trust
     * @return String representing date we started trusting this org
     */
    public static String getTrustedSinceString(User user, Org org, Org trustOrg) {
        Date since = getTrustedSince(user, org, trustOrg);
        if (since == null) {
            return null;
        }
        return LocalizationService.getInstance().formatDate(since);
    }

    /**
     * Returns the date which this org trusted the supplied orgId
     * @param user currently logged in user
     * @param orgTo Org to calculate the number of System migrations to
     * @param orgFrom Org to calculate the number of System migrations from
     * @return number of systems migrated to OrgIn
     */
    public static Long getMigratedSystems(User user, Org orgTo, Org orgFrom) {
        if (!user.hasRole(RoleFactory.ORG_ADMIN)) {
            throw getNoAdminError(RoleFactory.ORG_ADMIN, "system migration data");
        }

        return OrgFactory.getMigratedSystems(orgTo.getId(), orgFrom.getId());
    }

    /**
     * Returns the date which this org trusted the supplied orgId
     * @param user currently logged in user
     * @param org Org calculate the number of channels from
     * @param orgTrust Org to calculate the number of channels to
     * @return number of systems migrated to OrgIn
     */
    public static Long getSharedChannels(User user, Org org, Org orgTrust) {
        if (!user.hasRole(RoleFactory.ORG_ADMIN)) {
            throw getNoAdminError(RoleFactory.ORG_ADMIN, "system migration data");
        }

        return OrgFactory.getSharedChannels(org.getId(), orgTrust.getId());
    }

    /**
     * Returns the date which this org trusted the supplied orgId
     * @param user currently logged in user
     * @param org Org calculate the number of channels from
     * @param orgTrust Org to calculate the number of channels to
     * @return number of systems orgTrust has subscribed to Org shared channels
     */
    public static Long getSharedSubscribedSys(User user, Org org, Org orgTrust) {
        if (!user.hasRole(RoleFactory.ORG_ADMIN)) {
            throw getNoAdminError(RoleFactory.ORG_ADMIN, "system channel data");
        }

        return OrgFactory.getSharedSubscribedSys(org.getId(), orgTrust.getId());
    }
    /**
     * Returns the total number of orgs on this satellite.
     * @param user User performing the query.
     * @return Total number of orgs.
     */
    public static List<Org> allOrgs(User user) {
        if (!user.hasRole(RoleFactory.SAT_ADMIN)) {
            throw getNoAdminError(RoleFactory.SAT_ADMIN, ORG_LIST);
        }

        return OrgFactory.lookupAllOrgs();
    }

    /**
     * Check if the passed in org is a valid name and raises an
     * exception if its invalid..
     * @param newOrgName the orgname to be applied
     * @throws ValidatorException in case of bad/duplicate name
     */
    public static void checkOrgName(String newOrgName) throws ValidatorException {
        if (newOrgName == null ||
                newOrgName.trim().isEmpty() ||
                newOrgName.trim().length() < 3 ||
                newOrgName.trim().length() > 128) {
            ValidatorException.raiseException("orgname.jsp.error");
        }
        else if (OrgFactory.lookupByName(newOrgName) != null) {
            ValidatorException.raiseException("error.org_already_taken", newOrgName);
        }
    }

    /**
     * Rename org and relevant objects containing org name
     * @param org org to update
     * @param newName new name for org
     */
    public static void renameOrg(Org org, String newName) {
        org.setName(newName);
        // Org's private channel family contains org name in it
        ChannelFamily cf = ChannelFamilyFactory.lookupByOrg(org);
        cf.setName(newName + " (" + org.getId() + ") " + "Channel Family");
    }

    /**
     * Sets the content lifecycle management patch synchronization config option.
     *
     * @param user the user performing the action
     * @param orgId the involved org id
     * @param value the config option value
     * @throws PermissionException if the user is not authorized to perform this action
     */
    public static void setClmSyncPatchesConfig(User user, long orgId, boolean value) {
        Org org = OrgFactory.lookupById(orgId);
        ensureOrgPermissions(user, org);
        org.getOrgConfig().setClmSyncPatches(value);
    }

    /**
     * Reads the content lifecycle management patch synchronization config option.
     *
     * @param user the user performing the action
     * @param orgId the involved org id
     * @return the value of the option
     * @throws PermissionException if the user is not authorized to perform this action
     */
    public static boolean getClmSyncPatchesConfig(User user, long orgId) {
        Org org = OrgFactory.lookupById(orgId);
        ensureOrgPermissions(user, org);
        return org.getOrgConfig().isClmSyncPatches();
    }

    private static void ensureOrgPermissions(User user, Org org) {
        if (!user.hasRole(ORG_ADMIN)) {
            throw new PermissionException(ORG_ADMIN);
        }
        if (!user.getOrg().equals(org)) {
            throw new PermissionException(String.format("User %s is not part of organization %s", user, org));
        }
    }
}
