/*
 * Copyright (c) 2009--2020 Red Hat, Inc.
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
package com.redhat.rhn.domain.errata;

import com.redhat.rhn.common.db.datasource.Row;
import com.redhat.rhn.domain.BaseDomainHelper;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.frontend.struts.Selectable;
import com.redhat.rhn.frontend.xmlrpc.InvalidParameterException;
import com.redhat.rhn.manager.errata.ErrataManager;

import org.apache.commons.collections.IteratorUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Errata - Class representation of the table rhnErrata.
 */
public class Errata extends BaseDomainHelper implements Selectable {

    private static Logger log = LogManager.getLogger(Errata.class);
    protected Set<Package> packages;

    private Set<Channel> channels = new HashSet<>();
    private Set<Cve> cves = new HashSet<>();
    private Long id;
    private String advisory;
    private String advisoryType;
    private AdvisoryStatus advisoryStatus = AdvisoryStatus.FINAL;
    private String product;
    private String description;
    private String synopsis;
    private String topic;
    private String solution;
    private Date issueDate;
    private Date updateDate;
    private String notes;
    private String rights;
    private String refersTo;
    private String advisoryName;
    private Long advisoryRel;
    private Boolean locallyModified;
    private Date lastModified;
    private Org org;
    private Set<Bug> bugs = new HashSet<>();
    private Set<ErrataFile> files;
    private Set<Keyword> keywords;
    private boolean selected;
    private String errataFrom;
    private Severity severity;

    /**
     * Getter for channels
     * @return channels to get
     */
    public Set<Channel> getChannels() {
        return channels;
    }

    /**
     * @param channelsIn sets channels
     */
    public void setChannels(Set<Channel> channelsIn) {
        this.channels = channelsIn;
    }

    /**
     * Adds a channel.
     * @param channelIn the channel to add
     */
    public void addChannel(Channel channelIn) {
        log.debug("addChannel called: {}", channelIn.getLabel());
        if (this.channels == null) {
            this.channels = new HashSet<>();
        }
        channels.add(channelIn);
    }

    /**
     * Getter for cloned
     * @return true if cloned
     */
    public boolean isCloned() {
        return false;
    }

    /**
     * @param cvesIn sets cves
     */
    public void setCves(Set<Cve> cvesIn) {
        this.cves = cvesIn;
    }

    /**
     * @return Returns cves
     */
    public Set<Cve> getCves() {
        return cves;
    }

    /**
     * Getter for id
     * @return Long to get
     */
    public Long getId() {
        return this.id;
    }

    /**
     * Setter for id
     * @param idIn to set
     */
    public void setId(Long idIn) {
        this.id = idIn;
    }

    /**
     * Getter for advisory
     * @return String to get
     */
    public String getAdvisory() {
        return this.advisory;
    }

    /**
     * Setter for advisory
     * @param advisoryIn to set
     */
    public void setAdvisory(String advisoryIn) {
        this.advisory = advisoryIn;
    }

    /**
     * Getter for advisoryType
     * @return String to get
     */
    public String getAdvisoryType() {
        return this.advisoryType;
    }

    /**
     * Setter for advisoryType
     * @param advisoryTypeIn to set
     */
    public void setAdvisoryType(String advisoryTypeIn) {
        this.advisoryType = advisoryTypeIn;
    }

    /**
     * Getter for advisoryStatus
     * @return String to get
     */
    public AdvisoryStatus getAdvisoryStatus() {
        return this.advisoryStatus;
    }

    /**
     * Setter for advisoryStatus
     * @param advisoryStatusIn to set
     */
    public void setAdvisoryStatus(AdvisoryStatus advisoryStatusIn) {
        this.advisoryStatus = advisoryStatusIn;
    }

    /**
     * Setter for advisoryStatus
     * @param advisoryStatusIn to set
     */
    public void setAdvisoryStatus(String advisoryStatusIn) {
        this.advisoryStatus = AdvisoryStatus.fromMetadata(advisoryStatusIn)
                .orElseThrow(() -> new InvalidParameterException("Invalid advisory status"));
    }

    /**
     * Getter for product
     * @return String to get
     */
    public String getProduct() {
        return this.product;
    }

    /**
     * Setter for product
     * @param productIn to set
     */
    public void setProduct(String productIn) {
        this.product = productIn;
    }

    /**
     * Getter for author
     * @return String to get
     */
    public String getErrataFrom() {
        return this.errataFrom;
    }

    /**
     * Setter for author
     * @param from to set
     */
    public void setErrataFrom(String from) {
        if (StringUtils.isEmpty(from)) {
            this.errataFrom = null;
        }
        else {
            this.errataFrom = from;
        }
    }

    /**
     * Getter for description
     * @return String to get
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Setter for description
     * @param descriptionIn to set
     */
    public void setDescription(String descriptionIn) {
        this.description = descriptionIn;
    }

    /**
     * Getter for synopsis
     * @return String to get
     */
    public String getSynopsis() {
        return this.synopsis;
    }

    /**
     * Getter for synopsis
     * @return String to get
     */
    public String getAdvisorySynopsis() {
        return getSynopsis();
    }

    /**
     * Setter for synopsis
     * @param synopsisIn to set
     */
    public void setSynopsis(String synopsisIn) {
        this.synopsis = synopsisIn;
    }

    /**
     * Getter for topic
     * @return String to get
     */
    public String getTopic() {
        return this.topic;
    }

    /**
     * Setter for topic
     * @param topicIn to set
     */
    public void setTopic(String topicIn) {
        this.topic = topicIn;
    }

    /**
     * Getter for solution
     * @return String to get
     */
    public String getSolution() {
        return this.solution;
    }

    /**
     * Setter for solution
     * @param solutionIn to set
     */
    public void setSolution(String solutionIn) {
        this.solution = solutionIn;
    }

    /**
     * Getter for issueDate
     * @return Date to get
     */
    public Date getIssueDate() {
        return this.issueDate;
    }

    /**
     * Setter for issueDate
     * @param issueDateIn to set
     */
    public void setIssueDate(Date issueDateIn) {
        this.issueDate = issueDateIn;
    }

    /**
     * Getter for updateDate
     * @return Date to get
     */
    public Date getUpdateDate() {
        return this.updateDate;
    }

    /**
     * Setter for updateDate
     * @param updateDateIn to set
     */
    public void setUpdateDate(Date updateDateIn) {
        this.updateDate = updateDateIn;
    }

    /**
     * Getter for notes
     * @return String to get
     */
    public String getNotes() {
        return this.notes;
    }

    /**
     * Setter for notes
     * @param notesIn to set
     */
    public void setNotes(String notesIn) {
        if (StringUtils.isEmpty(notesIn)) {
            this.notes = null;
        }
        else {
            this.notes = notesIn;
        }
    }

    /**
     * Getter for rights
     * @return the rights for this errata
     */
    public String getRights() {
        return rights;
    }

    /**
     * Setter for rights
     * @param rightsIn value to set for this errata
     */
    public void setRights(String rightsIn) {
        if (StringUtils.isEmpty(rightsIn)) {
            this.rights = null;
        }
        else {
            this.rights = rightsIn;
        }
    }

    /**
     * Getter for org
     * @return Org to get
     */
    public Org getOrg() {
        return this.org;
    }

    /**
     * Setter for org
     * @param orgIn to set
     */
    public void setOrg(Org orgIn) {
        this.org = orgIn;
    }

    /**
     * Getter for refersTo
     * @return String to get
     */
    public String getRefersTo() {
        return this.refersTo;
    }

    /**
     * Setter for refersTo
     * @param refersToIn to set
     */
    public void setRefersTo(String refersToIn) {
        if (StringUtils.isEmpty(refersToIn)) {
            this.refersTo = null;
        }
        else {
            this.refersTo = refersToIn;
        }
    }

    /**
     * Getter for advisoryName
     * @return String to get
     */
    public String getAdvisoryName() {
        return this.advisoryName;
    }

    /**
     * Setter for advisoryName
     * @param advisoryNameIn to set
     */
    public void setAdvisoryName(String advisoryNameIn) {
        this.advisoryName = advisoryNameIn;
    }

    /**
     * Getter for advisoryRel
     * @return Long to get
     */
    public Long getAdvisoryRel() {
        return this.advisoryRel;
    }

    /**
     * Setter for advisoryRel
     * @param advisoryRelIn to set
     */
    public void setAdvisoryRel(Long advisoryRelIn) {
        this.advisoryRel = advisoryRelIn;
    }

    /**
     * Getter for severity
     * @return Severity to get
     */
    public Severity getSeverity() {
        return this.severity;
    }

    /**
     * Setter for severity
     * @param s Severity to set
     */
    public void setSeverity(Severity s) {
        this.severity = s;
    }

    /**
     * Getter for locallyModified
     * @return Boolean to get
     */
    public Boolean getLocallyModified() {
        return this.locallyModified;
    }

    /**
     * Setter for locallyModified
     * @param locallyModifiedIn to set
     */
    public void setLocallyModified(Boolean locallyModifiedIn) {
        this.locallyModified = locallyModifiedIn;
    }

    /**
     * Getter for lastModified
     * @return Date to get
     */
    public Date getLastModified() {
        return this.lastModified;
    }

    /**
     * Setter for lastModified
     * @param lastModifiedIn to set
     */
    public void setLastModified(Date lastModifiedIn) {
        this.lastModified = lastModifiedIn;
    }

    /**
     * Returns true if the advisory is a Product Enhancement.
     * @return true if the advisory is a Product Enhancement.
     */
    public boolean isProductEnhancement() {
        return "Product Enhancement Advisory".equals(getAdvisoryType());
    }

    /**
     * Returns true if the advisory is a Security Advisory.
     * @return true if the advisory is a Security Advisory.
     */
    public boolean isSecurityAdvisory() {
        return "Security Advisory".equals(getAdvisoryType());
    }

    /**
     * Returns true if the advisory is a Bug Fix.
     * @return true if the advisory is a Bug Fix.
     */
    public boolean isBugFix() {
        return "Bug Fix Advisory".equals(getAdvisoryType());
    }

    /**
     * Removes a bug from the bugs set
     * @param bugId id of the bug to remove
     */
    public void removeBug(Long bugId) {
        Bug deleteme = null; // the bug to delete
        for (Bug bug : getBugs()) {
            if (bug.getId().equals(bugId)) {
                deleteme = bug; // we found it!!!
                break;
            }
        }
        getBugs().remove(deleteme);
        ErrataFactory.removeBug(deleteme);
    }

    /**
     * Adds a bug to the bugs set
     * @param bugIn The bug to add
     */
    public void addBug(Bug bugIn) {
        // add bug to bugs
        this.getBugs().add(bugIn);
        // set errata for bugIn
        bugIn.setErrata(this);
    }

    /**
     * @return Returns the bugs.
     */
    public Set<Bug> getBugs() {
        return bugs;
    }

    /**
     * @param b The bugs to set.
     */
    public void setBugs(Set b) {
        this.bugs = b;
    }

    /**
     * Adds a file to the file set
     * @param fileIn The file to add
     */
    public void addFile(ErrataFile fileIn) {
        if (this.files == null) {
            this.files = new HashSet<>();
        }

        this.files.add(fileIn);
        fileIn.setErrata(this);
    }

    /**
     * Removes a file from the files set
     * @param fileId The id of the file to remove
     */
    public void removeFile(Long fileId) {
        ErrataFile deleteme = null; // the bug to delete
        for (ErrataFile file : this.files) {
            if (file.getId().equals(fileId)) {
                deleteme = file; // we found it!!!
                break;
            }
        }
        this.files.remove(deleteme);
        ErrataFactory.removeFile(deleteme);
    }

    /**
     * @return Returns the files.
     */
    public Set<ErrataFile> getFiles() {
        return this.files;
    }

    /**
     * @param f The files to set.
     */
    public void setFiles(Set<ErrataFile> f) {
        this.files = f;
    }

    /**
     * Convienience method so we can add keywords logically Adds a keyword to
     * the keywords set
     * @param keywordIn The keyword to add.
     */
    public void addKeyword(String keywordIn) {
        if (this.keywords == null) {
            this.keywords = new HashSet<>();
        }
        for (Keyword k : getKeywords()) {
            if (k.getKeyword().equals(keywordIn)) {
                return;
            }
        }


        /*
         * Bah... this stinks since a keyword is just a string, but we have to
         * set the created/modified fields in the db.
         */
        Keyword k = new Keyword();
        k.setKeyword(keywordIn);
        addKeyword(k);
        k.setErrata(this);
    }

    /**
     * Adds a keyword to the keywords set.
     * @param keywordIn The keyword to add.
     */
    public void addKeyword(Keyword keywordIn) {
        if (this.keywords == null) {
            this.keywords = new HashSet<>();
        }
        // add keyword to set
        keywords.add(keywordIn);
        // set errata for keywordIn

    }

    /**
     * Checks whether a keyword is already associated with an erratum.
     * @param keywordIn The keyword to check.
     * @return returns whether keyword is already associated with given erratum
     */
    public boolean containsKeyword(String keywordIn) {
        if (this.keywords == null) {
            return false;
        }
        for (Keyword k : this.keywords) {
            if (k.getKeyword().equals(keywordIn)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return Returns the keywords.
     */
    public Set<Keyword> getKeywords() {
        return keywords;
    }

    /**
     * @param k The keywords to set.
     */
    public void setKeywords(Set<Keyword> k) {
        this.keywords = k;
    }

    /**
     * Search for the given keyword in the set
     * @param s The keyword to search for
     * @return true if keyword was found
     */
    public boolean hasKeyword(String s) {
        return containsKeyword(s);
    }

    /**
     * Adds a package to the packages set
     * @param packageIn The package to add.
     */
    public void addPackage(Package packageIn) {
        if (this.packages == null) {
            this.packages = new HashSet<>();
        }
        packages.add(packageIn);
    }

    /**
     * Removes a package from the packages set.
     * @param packageIn The package to remove.
     */
    public void removePackage(Package packageIn) {
        packages.remove(packageIn);
    }

    /**
     * @return Returns the packages.
     */
    public Set<Package> getPackages() {
        return packages;
    }

    /**
     * @param p The packages to set.
     */
    public void setPackages(Set<Package> p) {
        this.packages = p;
    }

    /**
     * Adds an Errata Notification
     * @param dateIn the date of the notification
     */
    public void addNotification(Date dateIn) {
        ErrataManager.clearErrataNotifications(this);
        for (Channel chan : getChannels()) {
            ErrataManager.addErrataNotification(id, chan.getId(), dateIn);
        }
    }

    /**
     * @return all errata notifications
     */
    public List<Row> getNotificationQueue() {
        return ErrataManager.listErrataNotifications(this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return getClass().getName() + " : " + id + " : " + advisory + " desc: " + description + " syn: " + synopsis;
    }

    /**
     * Clears out the Channels associated with this errata.
     */
    public void clearChannels() {
        if (this.getChannels() != null) {
            this.getChannels().clear();
        }
        Iterator<ErrataFile> i = IteratorUtils.getIterator(this.getFiles());
        while (i.hasNext()) {
            ErrataFile pf = i.next();
            pf.getChannels().clear();
        }
    }

    /**
     * @return whether this object is selectable for RhnSet
     */
    @Override
    public boolean isSelectable() {
        return true;
    }

    /**
     * @return the selected
     */
    @Override
    public boolean isSelected() {
        return selected;
    }

    /**
     * @param isSelected the selected to set
     */
    @Override
    public void setSelected(boolean isSelected) {
        this.selected = isSelected;
    }

    /**
     * @return the selection key
     */
    @Override
    public String getSelectionKey() {
        return String.valueOf(getId());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Errata)) {
            return false;
        }
        Errata e = (Errata) obj;
        EqualsBuilder eb = new EqualsBuilder();
        eb.append(this.getAdvisory(), e.getAdvisory());
        eb.append(this.getAdvisoryName(), e.getAdvisoryName());
        eb.append(this.getAdvisoryRel(), e.getAdvisoryRel());
        eb.append(this.getAdvisorySynopsis(), e.getAdvisorySynopsis());
        eb.append(this.getOrg(), e.getOrg());
        return eb.isEquals();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        HashCodeBuilder eb = new HashCodeBuilder();
        eb.append(this.getAdvisory());
        eb.append(this.getAdvisoryName());
        eb.append(this.getAdvisoryRel());
        eb.append(this.getAdvisorySynopsis());
        eb.append(this.getOrg());
        return eb.toHashCode();
    }
}
