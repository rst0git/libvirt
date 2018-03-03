/*
 * Copyright (C) 2016 Katerina Koukiou
 *
 * lxc_criu.c: Helper functions for checkpoint/restore of linux containers
 *
 * Authors:
 *  Katerina Koukiou <k.koukiou at gmail.com>
 *  Radostin Stoyanov <r.stoyanov.14 at abedeen.ac.uk>
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

int lxcCriuDump(virLXCDriverPtr driver ATTRIBUTE_UNUSED,
                virDomainObjPtr vm,
                const char *checkpointDir)
{
    int checkpointDirFd;
    int ret = -1;
    pid_t initpid;
    virCommandPtr cmd;
    struct stat sb;
    char *ptsPath = NULL;
    char *ttyInfoPath = NULL;
    char *ttyInfo = NULL;
    int status;
    char *criu = NULL;

    criu = virFindFileInPath("criu");
    if (!criu) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find criu binary"));
       VIR_FREE(criu);
       return -1;
    }
    cmd = virCommandNew(criu);

    initpid = ((virLXCDomainObjPrivatePtr) vm->privateData)->initpid;

    if (virFileMakePath(checkpointDir) < 0) {
        virReportSystemError(errno, _("Failed to mkdir %s"), checkpointDir);
        return -1;
    }

    checkpointDirFd = open(checkpointDir, O_DIRECTORY);
    if (checkpointDirFd < 0) {
        virReportSystemError(errno,
                             _("Failed to open directory %s"), checkpointDir);
        return -1;
    }

    /* The master pair of the /dev/pts device lives outside from what is dumped
     * inside the libvirt-lxc process. Add the slave pair as an external tty
     * otherwise criu will fail.
     */
    if (virAsprintf(&ptsPath, "/proc/%d/root/dev/pts/0", initpid) < 0)
        goto cleanup;

    if (stat(ptsPath, &sb) < 0) {
        virReportSystemError(errno, _("Unable to stat %s"), ptsPath);
        goto cleanup;
    }

    if (virAsprintf(&ttyInfoPath, "%s/tty.info", checkpointDir) < 0)
        goto cleanup;

    if (virAsprintf(&ttyInfo, "tty[%llx:%llx]",
                    (long long unsigned) sb.st_rdev,
                    (long long unsigned) sb.st_dev) < 0)
        goto cleanup;

    if (virFileWriteStr(ttyInfoPath, ttyInfo, 0600) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to write tty info to %s"), ttyInfoPath);
        goto cleanup;
    }

    virCommandAddArg(cmd, "dump");
    virCommandAddArg(cmd, "--tree");
    virCommandAddArgFormat(cmd, "%d", initpid);
    virCommandAddArgList(cmd,
        "--images-dir", checkpointDir,
        "--tcp-established",
        "--log-file", "dump.log",
        "-v4",
        "--file-locks",
        "--link-remap",
        "--force-irmap",
        "--manage-cgroups=full",
        "--enable-fs", "hugetlbfs",
        "--enable-fs", "tracefs",
        "--external", "mnt[]{:ms}",
        "--external", "mnt[/proc/meminfo]:fuse",
        "--external", "mnt[/dev/console]:console",
        "--external", "mnt[/dev/tty1]:tty1",
        "--external", ttyInfo,
        NULL
    );

    virCommandAddEnvString(cmd, "PATH=/bin:/sbin");
    virCommandRawStatus(cmd);
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(checkpointDirFd);
    VIR_FREE(ptsPath);
    VIR_FREE(ttyInfoPath);
    VIR_FREE(ttyInfo);
    virCommandFree(cmd);

    return (ret < 0) ? ret : status;
}


int lxcCriuRestore(virDomainDefPtr def, int restorefd,
                   int ttyfd)
{
    int ret = -1;
    virCommandPtr cmd;
    char *ttyInfo = NULL;
    char *inheritfd = NULL;
    char *ttyInfoPath = NULL;
    char *checkpointFd = NULL;
    char *checkpointDir = NULL;
    virDomainFSDefPtr root;
    gid_t *groups = NULL;
    int ngroups;
    char *criu = NULL;

    criu = virFindFileInPath("criu");
    if (!criu) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find criu binary"));
       VIR_FREE(criu);
       return -1;
    }

    cmd = virCommandNew(criu);
    virCommandAddArg(cmd, "restore");

    if (virAsprintf(&checkpointFd, "/proc/self/fd/%d", restorefd) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to write checkpoint dir path"));
        goto cleanup;
    }

    if (virFileResolveLink(checkpointFd, &checkpointDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to readlink checkpoint dir path"));
        goto cleanup;
    }

    virCommandAddArgList(cmd,
        "--pidfile", "pidfile",
        "--restore-detached",
        "--restore-sibling",
        "--tcp-established",
        "--file-locks",
        "--link-remap",
        "--manage-cgroups=full",
        "--enable-fs", "hugetlbfs",
        "--enable-fs", "tracefs",
        "--images-dir", checkpointDir,
        "--log-file", "restore.log",
        "-v4",
        "--external", "mnt[]{:ms}",
        "--external", "mnt[fuse]:/proc/meminfo",
        "--external", "mnt[console]:/dev/console",
        "--external", "mnt[tty1]:/dev/tty1",
        NULL
    );

    /* Restore external tty from tty.info file */
    if (virAsprintf(&ttyInfoPath, "%s/tty.info", checkpointDir) < 0)
        goto cleanup;

    if (virFileReadAll(ttyInfoPath, 1024, &ttyInfo) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read tty info from %s"), ttyInfoPath);
        goto cleanup;
    }
    if (virAsprintf(&inheritfd, "fd[%d]:%s", ttyfd, ttyInfo) < 0)
        goto cleanup;

    virCommandAddArgList(cmd, "--inherit-fd", inheritfd, NULL);

    root = virDomainGetFilesystemForTarget(def, "/");
    virCommandAddArgList(cmd, "--root", root->src->path, NULL);

    virCommandAddEnvString(cmd, "PATH=/bin:/sbin");

    if ((ngroups = virGetGroupList(virCommandGetUID(cmd), virCommandGetGID(cmd), &groups)) < 0)
        goto cleanup;

    /* If virCommandExec returns here we have an error */
    ignore_value(virCommandExec(cmd, groups, ngroups));

    ret = -1;

 cleanup:
    VIR_FREE(ttyInfoPath);
    VIR_FREE(ttyInfo);
    VIR_FREE(inheritfd);
    VIR_FREE(checkpointDir);
    VIR_FREE(checkpointFd);
    virCommandFree(cmd);

    return ret;
}