/*
 * Copyright (C) 2016 Katerina Koukiou
 *
 * lxc_criu.c: wrapper functions for CRIU C API to be used for lxc migration
 *
 * Authors:
 *  Katerina Koukiou <k.koukiou@gmail.com>
 *  Radostin Stoyanov <rstoyanov1@gmail.com>
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
 */

#include <config.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "virobject.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "vircommand.h"
#include "virstring.h"
#include "viralloc.h"

#include "lxc_domain.h"
#include "lxc_driver.h"
#include "lxc_criu.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_criu");

#ifdef WITH_CRIU

#include <criu/criu.h>

int lxcCriuDump(virLXCDriverPtr driver ATTRIBUTE_UNUSED,
                virDomainObjPtr vm,
                const char *checkpointdir)
{
    int fd;
    int pidfile_fd;
    char *pidfile = NULL;
    char *path = NULL;
    char *tty_info_path = NULL;
    char *ttyinfo = NULL;
    struct stat sb;
    virLXCDomainObjPrivatePtr priv;
    int ret = -1;

    if (virFileMakePath(checkpointdir) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %s"), checkpointdir);
        return -1;
    }

    fd = open(checkpointdir, O_DIRECTORY);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("Failed to open directory %s"), checkpointdir);
        return -1;
    }

    criu_init_opts();
    criu_set_images_dir_fd(fd);
    criu_set_log_file((char *)"dump.log");
    criu_set_log_level(4);  /* LOG_DEBUG = 4 */

    priv = vm->privateData;
    criu_set_pid(priv->initpid);

    /* Output the container's pid to pidfile */
    if (virAsprintf(&pidfile, "%s/pidfile", checkpointdir) < 0)
        goto cleanup;

    if ((pidfile_fd = open(pidfile, O_WRONLY | O_EXCL | O_CREAT, 0600)) == -1) {
        virReportSystemError(errno, _("Can't open pidfile: %s"), pidfile);
		return -1;
	}

	dprintf(pidfile_fd, "%d", priv->initpid);
	close(pidfile_fd);

    criu_set_tcp_established(true);
    criu_set_file_locks(true);
    criu_set_link_remap(true);
    criu_set_force_irmap(true);
    criu_set_manage_cgroups(true);
    criu_set_manage_cgroups_mode(CRIU_CG_MODE_FULL);
    criu_set_ext_masters(true);
    criu_set_ext_sharing(true);
    criu_set_auto_ext_mnt(true);

    criu_add_enable_fs((char *)"hugetlbfs");
    criu_add_enable_fs((char *)"tracefs");

    criu_set_leave_running(false);

    criu_add_ext_mount((char *)"/proc/meminfo", (char *)"fuse");
    criu_add_ext_mount((char *)"/dev/console", (char *)"console");
    criu_add_ext_mount((char *)"/dev/tty1", (char *)"tty1");

    if (virAsprintf(&path, "/proc/%d/root/dev/pts/0", priv->initpid) < 0)
        goto cleanup;

    if (stat(path, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to stat %s"), path);
        goto cleanup;
    }

    if (virAsprintf(&tty_info_path, "%s/tty.info", checkpointdir) < 0)
        goto cleanup;

    if (virAsprintf(&ttyinfo, "tty[%x:%x]",
                   (unsigned int)sb.st_rdev, (unsigned int)sb.st_dev) < 0)
        goto cleanup;

    if (virFileWriteStr(tty_info_path, ttyinfo, 0666) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to write tty info to %s"), tty_info_path);
        goto cleanup;
    }

    VIR_DEBUG("tty.info: tty[%x:%x]",
             (unsigned int)sb.st_dev, (unsigned int)sb.st_rdev);
    criu_add_external(ttyinfo);

    VIR_DEBUG("About to checkpoint vm: %s pid=%d", vm->def->name, priv->initpid);
    ret = criu_dump();

 cleanup:
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(path);
    VIR_FREE(tty_info_path);
    VIR_FREE(ttyinfo);

    return ret;
}

int lxcCriuRestore(virDomainDefPtr def, int restorefd,
                   int ttyfd)
{
    char *ttyinfo = NULL;
    char *inheritfd = NULL;
    char *tty_info_path = NULL;
    char *checkpointfd = NULL;
    char *checkpointdir = NULL;
    char *rootfs_mount = NULL;
    gid_t *groups = NULL;
    int ret = -1;

    if (virAsprintf(&checkpointfd, "/proc/self/fd/%d", restorefd) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to write checkpoint dir path"));
        goto cleanup;
    }

    if (virFileResolveLink(checkpointfd, &checkpointdir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to readlink checkpoint dir path"));
        goto cleanup;
    }

    criu_init_opts();
    criu_set_images_dir_fd(restorefd);

    criu_set_log_file((char *)"restore.log");
    criu_set_log_level(4);  /* LOG_DEBUG = 4 */
    criu_set_manage_cgroups(true);
    criu_set_manage_cgroups_mode(CRIU_CG_MODE_FULL);
    criu_set_tcp_established(true);
    criu_set_file_locks(true);
    criu_set_link_remap(true);
    criu_set_force_irmap(true);
    criu_set_auto_ext_mnt(true);
    criu_set_ext_masters(true);
    criu_set_ext_sharing(true);

    criu_add_enable_fs((char *)"hugetlbfs");
    criu_add_enable_fs((char *)"tracefs");

    criu_add_ext_mount((char *)"/proc/meminfo", (char *)"fuse");
    criu_add_ext_mount((char *)"/dev/console", (char *)"console");
    criu_add_ext_mount((char *)"/dev/tty1", (char *)"tty1");

    if (VIR_STRDUP_QUIET(rootfs_mount, "/tmp/lxc-ct-XXXXXX") < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to write rootfs dir mount path"));
        goto cleanup;
    }

    if (mkdtemp(rootfs_mount) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to create tmp rootfs dir mount"));
        goto cleanup;
    }

    if (mount("", "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed remount /"));
        goto cleanup;
    }

    if (mount(rootfs_mount, rootfs_mount, NULL, MS_BIND, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to bind mount rootfs dir"));
        goto cleanup;
    }

    criu_set_root(rootfs_mount);

    /* Restore cgroup properties if only cgroup has been created by criu,
     * otherwise do not restore properies
     */
    criu_set_manage_cgroups_mode(CRIU_CG_MODE_SOFT);

    /* Restore external tty that was saved in tty.info file
     */
    if (virAsprintf(&tty_info_path, "%s/tty.info", checkpointdir) < 0)
        goto cleanup;

    if (virFileReadAll(tty_info_path, 1024, &ttyinfo) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read tty info from %s"), tty_info_path);
        goto cleanup;
    }

    criu_add_inherit_fd(ttyfd, ttyinfo);

    VIR_DEBUG("About to restore vm: %s", def->name);
    ret = criu_restore();

 cleanup:
    VIR_FREE(tty_info_path);
    VIR_FREE(ttyinfo);
    VIR_FREE(inheritfd);
    VIR_FREE(groups);
    VIR_FREE(checkpointdir);
    VIR_FREE(rootfs_mount);
    VIR_FREE(checkpointfd);

    return ret;
}
#else
int lxcCriuDump(virLXCDriverPtr driver ATTRIBUTE_UNUSED,
                virDomainObjPtr vm ATTRIBUTE_UNUSED,
                const char *checkpointdir ATTRIBUTE_UNUSED)
{
    virReportUnsupportedError();
    return -1;
}

int lxcCriuRestore(virDomainDefPtr def ATTRIBUTE_UNUSED,
                   int fd ATTRIBUTE_UNUSED,
                   int ttyfd ATTRIBUTE_UNUSED)
{
    virReportUnsupportedError();
    return -1;
}
#endif

