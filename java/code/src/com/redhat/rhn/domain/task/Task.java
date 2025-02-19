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
package com.redhat.rhn.domain.task;

import com.redhat.rhn.domain.org.Org;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

/**
 * Task
 */
@Entity
@Table(name = "rhnTaskQueue")
@IdClass(Task.TaskId.class)
public class Task implements Serializable {

    public static class TaskId implements Serializable {
        private String name;
        private Long data;
        private Date earliest;
        private Org org;

        @Override
        public boolean equals(Object oIn) {
            if (this == oIn) {
                return true;
            }

            if (oIn == null || getClass() != oIn.getClass()) {
                return false;
            }

            TaskId taskId = (TaskId) oIn;

            return new EqualsBuilder()
                    .append(name, taskId.name)
                    .append(data, taskId.data)
                    .append(earliest, taskId.earliest)
                    .append(org, taskId.org)
                    .isEquals();
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder(17, 37)
                    .append(name)
                    .append(data)
                    .append(earliest)
                    .append(org)
                    .toHashCode();
        }
    }

    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "task_name", nullable = false, length = 64)
    private String name;

    @Id
    @Column(name = "task_data")
    private Long data;

    @Column
    private int priority;

    @Id
    @Column(nullable = false)
    private Date earliest;

    @Id
    @ManyToOne(optional = false)
    @JoinColumn(name = "org_id")
    private Org org;


    /**
     * @return Returns the data.
     */
    public Long getData() {
        return data;
    }

    /**
     * @param dataIn The data to set.
     */
    public void setData(Long dataIn) {
        this.data = dataIn;
    }

    /**
     * @return Returns the earliest.
     */
    public Date getEarliest() {
        return earliest;
    }

    /**
     * @param earliestIn The earliest to set.
     */
    public void setEarliest(Date earliestIn) {
        this.earliest = earliestIn;
    }

    /**
     * @return Returns the name.
     */
    public String getName() {
        return name;
    }

    /**
     * @param nameIn The name to set.
     */
    public void setName(String nameIn) {
        this.name = nameIn;
    }

    /**
     * @return Returns the org.
     */
    public Org getOrg() {
        return org;
    }

    /**
     * @param orgIn The org to set.
     */
    public void setOrg(Org orgIn) {
        this.org = orgIn;
    }

    /**
     * @return Returns the priority.
     */
    public int getPriority() {
        return priority;
    }

    /**
     * @param priorityIn The priority to set.
     */
    public void setPriority(int priorityIn) {
        this.priority = priorityIn;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Task)) {
            return false;
        }
        Task castOther = (Task) other;
        return new EqualsBuilder().append(org, castOther.org)
                                  .append(name, castOther.name)
                                  .append(data, castOther.data)
                                  .append(priority, castOther.priority)
                                  .append(earliest, castOther.earliest)
                                  .isEquals();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(org)
                                    .append(name)
                                    .append(data)
                                    .append(priority)
                                    .append(earliest)
                                    .toHashCode();
    }
}
