--
-- Copyright (c) 2008--2018 Red Hat, Inc.
--
-- This software is licensed to you under the GNU General Public License,
-- version 2 (GPLv2). There is NO WARRANTY for this software, express or
-- implied, including the implied warranties of MERCHANTABILITY or FITNESS
-- FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
-- along with this software; if not, see
-- http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
--
-- Red Hat trademarks are not licensed under GPLv2. No permission is
-- granted to use or replicate Red Hat trademarks that are incorporated
-- in this software or its documentation.
--


CREATE TABLE rhnChannelComps
(
    id                 NUMERIC NOT NULL
                           CONSTRAINT rhn_channelcomps_id_pk PRIMARY KEY,
    channel_id         NUMERIC NOT NULL
                           CONSTRAINT rhn_channelcomps_cid_fk
                               REFERENCES rhnChannel (id)
                               ON DELETE CASCADE,
    relative_filename  VARCHAR(256) NOT NULL,
    last_modified      TIMESTAMPTZ
                           DEFAULT (current_timestamp) NOT NULL,
    created            TIMESTAMPTZ
                           DEFAULT (current_timestamp) NOT NULL,
    modified           TIMESTAMPTZ
                           DEFAULT (current_timestamp) NOT NULL,
    comps_type_id      NUMERIC NOT NULL
                          CONSTRAINT rhn_channelcomps_comps_type_fk
                               REFERENCES rhnCompsType(id),
    CONSTRAINT rhn_channelcomps_cid_ctype_filename_uq
        UNIQUE(channel_id, comps_type_id, relative_filename)
)

;

CREATE INDEX rhn_channelcomps_cid_ctype_idx
    ON rhnChannelComps (channel_id, comps_type_id)
    ;

CREATE SEQUENCE rhn_channelcomps_id_seq START WITH 101;

