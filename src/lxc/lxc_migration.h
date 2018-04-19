/*
 * lxc_migration.h: lxc migration handling
 *
 * Copyright (C) 2016 Katerina Koukiou
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Katerina Koukiou <k.koukiou@gmail.com>
 */

#ifndef LXC_MIGRATION_H
# define LXC_MIGRATION_H

# include "lxc_conf.h"

# define LXC_MIGRATION_FLAGS                    \
    (VIR_MIGRATE_LIVE |                         \
     VIR_MIGRATE_UNDEFINE_SOURCE |              \
     VIR_MIGRATE_PAUSED)

/* All supported migration parameters and their types. */
# define LXC_MIGRATION_PARAMETERS                               \
    VIR_MIGRATE_PARAM_URI,              VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_DEST_NAME,        VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_DEST_XML,         VIR_TYPED_PARAM_STRING, \
    NULL

char *
lxcDomainMigrationBegin(virConnectPtr conn,
                        virDomainObjPtr vm,
                        const char *xmlin);

virDomainDefPtr
lxcDomainMigrationPrepareDef(virLXCDriverPtr driver,
                             const char *dom_xml,
                             const char *dname);

int
lxcDomainMigrationPrepare(virConnectPtr dconn,
                          virDomainDefPtr def,
                          const char *uri_in,
                          char **uri_out,
                          unsigned int flags);

int
lxcDomainMigrationPerform(virLXCDriverPtr driver,
                          virDomainObjPtr vm,
                          const char *dom_xml,
                          const char *dconnuri,
                          const char *uri_str,
                          const char *dname,
                          unsigned int flags);

virDomainPtr
lxcDomainMigrationFinish(virConnectPtr dconn,
                         virDomainObjPtr vm,
                         unsigned int flags,
                         int cancelled);

int
lxcDomainMigrationConfirm(virLXCDriverPtr driver,
                          virDomainObjPtr vm,
                          unsigned int flags,
                          int cancelled);
#endif /* LXC_MIGRATION_H */
