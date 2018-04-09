/*
 * lxc_migration.c: methods for handling lxc migration
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Katerina Koukiou <k.koukiou@gmail.com>
 */

#include <config.h>

#include "fcntl.h"
#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "virconf.h"
#include "datatypes.h"
#include "viralloc.h"
#include "viruuid.h"
#include "vircommand.h"
#include "virstring.h"
#include "virobject.h"
#include "virfile.h"
#include "rpc/virnetsocket.h"
#include "lxc_domain.h"
#include "lxc_driver.h"
#include "lxc_conf.h"
#include "lxc_migration.h"
#include "lxc_criu.h"
#include "lxc_process.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_migration");

typedef struct _lxcMigrationDstArgs {
    virObject parent;

    int recvfd;
    virConnectPtr conn;
    virDomainObjPtr vm;
    unsigned int flags;

    /* for freeing listen sockets */
    virNetSocketPtr *socks;
    size_t nsocks;
} lxcMigrationDstArgs;

static virClassPtr lxcMigrationDstArgsClass;

static void
lxcMigrationDstArgsDispose(void *obj)
{
    lxcMigrationDstArgs *args = obj;

    VIR_FREE(args->socks);
}

static int
lxcMigrationDstArgsOnceInit(void)
{
    if (!(lxcMigrationDstArgsClass = virClassNew(virClassForObject(),
                                                 "lxcMigrationDstArgs",
                                                 sizeof(lxcMigrationDstArgs),
                                                 lxcMigrationDstArgsDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(lxcMigrationDstArgs)

static void
lxcDoMigrateReceive(void *opaque)
{
    lxcMigrationDstArgs *args = opaque;
    virNetSocketPtr *socks = args->socks;
    size_t nsocks = args->nsocks;
    virLXCDriverPtr driver = args->conn->privateData;
    virDomainObjPtr vm = args->vm;
    int recvfd = args->recvfd;
    size_t i;
    int checkpointfd;
    int restorefd;
    int nbytes;
    char buffer[256];
    unsigned int fdflags;
    bool remove_dom = 0;
    int ret = 0;
    virCommandPtr cmd = NULL;

    /*
     * After dup system call the two descriptors do not share file
     * descriptor flags.
     * Thus, we have to set blocking flag again.
     * TODO: Is there a VIR-smthing wrapper function for this?
     */
    fdflags = fcntl(recvfd, F_GETFL, 0);
    if (fdflags == -1)
        goto cleanup;
    /* Clear the non blocking flag. */
    fdflags &= ~O_NONBLOCK;
    if (fcntl(recvfd, F_SETFL, fdflags) == -1)
        goto cleanup;

    /*
     * Store the files received in recvfd a tar file to send through socket.
     * Then untar the file into a directory and give that fd, to
     * virLXCProcessStart to restore the container from the image files.
     */
    checkpointfd = open("checkpoint.tar.gz",
                  O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (checkpointfd == -1) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("Open file failed"));
        goto cleanup;
    }
    do {
        nbytes = saferead(recvfd, buffer, 256);
        if (nbytes < 0) {
            virReportSystemError(errno, "%s", _("Read from socket failed"));
            goto out;
        } else if (nbytes == 0) {
            /* EOF; get out of here */
            break;
        } else {
            if (safewrite(checkpointfd, buffer, nbytes) != nbytes) {
                virReportSystemError(errno, "%s", _("Write to file failed"));
                goto out;
            }
        }
    } while (nbytes > 0);

    cmd = virCommandNewArgList("tar", "-zxvf", "checkpoint.tar.gz", NULL);
    if (virCommandRun(cmd, NULL) < 0) {
       virReportError(VIR_ERR_INTERNAL_ERROR,
                      "%s", _("Can't untar checkpoint data"));
        goto out;
    }

    restorefd = open("./checkpointdir", O_DIRECTORY);
    if (restorefd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Can't open images dir"));
        goto out;
    }

    ret = virLXCProcessStart(args->conn, driver, vm,
                             0, NULL,
                             0, restorefd,
                             VIR_DOMAIN_RUNNING_MIGRATED);

    if (ret < 0 && !vm->persistent)
        remove_dom = true;

    VIR_FORCE_CLOSE(restorefd);

 out:
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(checkpointfd);

    /* TODO: Delete checkpoint directory */
    /* Leave it there for now to check on the logs */
    cmd = virCommandNewArgList("rm", "-f", "checkpoint.tar.gz", NULL);
    if (virCommandRun(cmd, NULL) < 0) {
       virReportError(VIR_ERR_INTERNAL_ERROR,
                      "%s", _("Can't delete checkpoint tar file"));
    }
    virCommandFree(cmd);

 cleanup:
    /* Remove all listen socks from event handler, and close them. */
    for (i = 0; i < nsocks; i++) {
        virNetSocketRemoveIOCallback(socks[i]);
        virNetSocketClose(socks[i]);
        virObjectUnref(socks[i]);
        socks[i] = NULL;
    }
    args->nsocks = 0;
    VIR_FORCE_CLOSE(recvfd);
    virObjectUnref(args);

    if (remove_dom && vm)
        virDomainObjListRemove(driver->domains, vm);
}


static void
lxcMigrateReceive(virNetSocketPtr sock,
                    int events ATTRIBUTE_UNUSED,
                    void *opaque)
{
    lxcMigrationDstArgs *args = opaque;
    virNetSocketPtr *socks = args->socks;
    size_t nsocks = args->nsocks;
    virNetSocketPtr client_sock;
    int recvfd = -1;
    virThread thread;
    size_t i;

    /* Accept migration connection */
    if (virNetSocketAccept(sock, &client_sock) < 0 || !client_sock) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to accept migration connection"));
        goto fail;
    }
    VIR_DEBUG("Accepted migration connection. "
              "Spawing thread to process migration data");
    recvfd = virNetSocketDupFD(client_sock, true);
    virObjectUnref(client_sock);

    /*
     * Avoid blocking the event loop. Start a thread to receive
     * the migration data
     */
    args->recvfd = recvfd;
    if (virThreadCreate(&thread, false,
                        lxcDoMigrateReceive, args) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to create thread for receiving migration data"));
        goto fail;
    }
    return;

 fail:
    /* Remove all listen socks from event handler, and close them. */
    for (i = 0; i < nsocks; i++) {
        virNetSocketUpdateIOCallback(socks[i], 0);
        virNetSocketRemoveIOCallback(socks[i]);
        virNetSocketClose(socks[i]);
        socks[i] = NULL;
    }
    args->nsocks = 0;
    VIR_FORCE_CLOSE(recvfd);
    virObjectUnref(args);
}

static int
lxcDoMigrateSend(virLXCDriverPtr driver,
                 virDomainObjPtr vm,
                 int sockfd)
{
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    int ret;
    int filefd;
    int nbytes;
    char buffer[256];
    char ebuf[1024];
    virCommandPtr cmd = NULL;


    if ((ret = lxcCriuDump(driver, vm, "checkpointdir")) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to checkpoint domain"));
        goto cleanup;
    }

    cmd = virCommandNewArgList("tar", "-zcvf", "checkpoint.tar.gz",
                               "checkpointdir", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if ((filefd = open("checkpoint.tar.gz", O_RDONLY)) < 0) {
        VIR_ERROR(_("Failed to open file checkpoint.tar.gz': %s"),
                    virStrerror(errno, ebuf, sizeof(ebuf)));
        goto cleanup;
    }

    while (1) {
        nbytes = saferead(filefd, buffer, 256);
        if (nbytes < 0) {
            VIR_ERROR(_("Failed to read from file checkpoint.tar.gz': %s"),
                        virStrerror(errno, ebuf, sizeof(ebuf)));
            goto abrt;
        } else if (nbytes == 0) {
            /* EOF; get out of here */
            goto abrt;
        } else {
            if (safewrite(sockfd, buffer, nbytes) != nbytes) {
                virReportSystemError(errno, "%s",
                                     _("Failed to write to socket"));
                goto abrt;
            }
        }
    }

 abrt:
    VIR_FORCE_CLOSE(filefd);

 cleanup:
    virCommandFree(cmd);
    virObjectUnref(cfg);
    /* TODO: After checkpoint data has been sent we want to keep things clean.
     * Don't forget to remove checkpoint directory and tar file
     * Keep some things for now just for debugging purposes*/

    cmd = virCommandNewArgList("rm", "-f", "checkpoint.tar.gz", NULL);
    if (virCommandRun(cmd, NULL) < 0) {
       virReportError(VIR_ERR_INTERNAL_ERROR,
                      "%s", _("Can't delete checkpoint tar file"));
    }
    virCommandFree(cmd);
    return ret;
}

static bool
lxcDomainMigrationIsAllowed(virDomainDefPtr def)
{
    /* Migration is not allowed if definition contains any hostdevs */
    if (def->nhostdevs > 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain has assigned host devices"));
        return false;
    }

    return true;
}

char *
lxcDomainMigrationBegin(virConnectPtr conn,
                        virDomainObjPtr vm,
                        const char *xmlin)
{
    virLXCDriverPtr driver = conn->privateData;
    virDomainDefPtr tmpdef = NULL;
    virDomainDefPtr def;
    virCapsPtr caps = NULL;

    char *xml = NULL;
    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto endjob;


    if (xmlin) {
        if (!(tmpdef = virDomainDefParseString(xmlin, caps,
                                               driver->xmlopt, NULL,
                                               VIR_DOMAIN_DEF_PARSE_INACTIVE)))
            goto endjob;

        if (!virDomainDefCheckABIStability(tmpdef, vm->def, driver->xmlopt))
            goto endjob;

        def = tmpdef;
    } else {
        def = vm->def;
    }
    if (!lxcDomainMigrationIsAllowed(def))
        goto endjob;

    /* For now we will only handle the case of live migration */
    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }
    xml = virDomainDefFormat(def, caps, VIR_DOMAIN_DEF_FORMAT_SECURE);

 cleanup:
    virDomainObjEndAPI(&vm);
    virDomainDefFree(tmpdef);
    return xml;

 endjob:
    virLXCDomainObjEndJob(driver, vm);
    goto cleanup;
}

virDomainDefPtr
lxcDomainMigrationPrepareDef(virLXCDriverPtr driver,
                               const char *dom_xml,
                               const char *dname)
{
    virCapsPtr caps = NULL;
    virDomainDefPtr def;
    char *name = NULL;

    if (!dom_xml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain XML passed"));
        return NULL;
    }

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        return NULL;

    if (!(def = virDomainDefParseString(dom_xml, caps, driver->xmlopt,
                                        NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

    if (dname) {
        name = def->name;
        if (VIR_STRDUP(def->name, dname) < 0) {
            virDomainDefFree(def);
            def = NULL;
        }
    }

 cleanup:
    virObjectUnref(caps);
    VIR_FREE(name);
    return def;
}

int
lxcDomainMigrationPrepare(virConnectPtr dconn,
                          virDomainDefPtr def,
                          const char *uri_in,
                          char **uri_out,
                          unsigned int flags)
{
    virLXCDriverPtr driver = dconn->privateData;
    virDomainObjPtr vm = NULL;
    char *hostname = NULL;
    unsigned short port;
    char portstr[100];
    virURIPtr uri = NULL;
    virNetSocketPtr *socks = NULL;
    size_t nsocks = 0;
    int nsocks_listen = 0;
    lxcMigrationDstArgs *args;
    size_t i;
    int ret = -1;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    /* Create socket connection to receive migration data */
    if (!uri_in) {
        if ((hostname = virGetHostname()) == NULL)
            goto cleanup;

        if (STRPREFIX(hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost,"
                             " but migration requires an FQDN"));
            goto cleanup;
        }

        if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
            goto cleanup;

        if (virAsprintf(uri_out, "tcp://%s:%d", hostname, port) < 0)
            goto cleanup;
    } else {
        if (!(STRPREFIX(uri_in, "tcp://"))) {
            /* not full URI, add prefix tcp:// */
            char *tmp;
            if (virAsprintf(&tmp, "tcp://%s", uri_in) < 0)
                goto cleanup;
            uri = virURIParse(tmp);
            VIR_FREE(tmp);
        } else {
            uri = virURIParse(uri_in);
        }

        if (uri == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unable to parse URI: %s"),
                           uri_in);
            goto cleanup;
        }

        if (uri->server == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing host in migration URI: %s"),
                           uri_in);
            goto cleanup;
        } else {
            hostname = uri->server;
        }

        if (uri->port == 0) {
            if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                goto cleanup;

        } else {
            port = uri->port;
        }

        if (virAsprintf(uri_out, "tcp://%s:%d", hostname, port) < 0)
            goto cleanup;
    }

    snprintf(portstr, sizeof(portstr), "%d", port);

    if (virNetSocketNewListenTCP(hostname, portstr,
                                AF_UNSPEC,
                                &socks, &nsocks) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Fail to create socket for incoming migration"));
        goto cleanup;
    }

    if (lxcMigrationDstArgsInitialize() < 0)
        goto cleanup;

    if (!(args = virObjectNew(lxcMigrationDstArgsClass)))
        goto cleanup;

    args->conn = dconn;
    args->vm = vm;
    args->flags = flags;
    args->socks = socks;
    args->nsocks = nsocks;
    VIR_DEBUG("nsocks = %zu", nsocks);
    for (i = 0; i < nsocks; i++) {
        if (virNetSocketSetBlocking(socks[i], true) < 0)
            continue;
        if (virNetSocketListen(socks[i], 1) < 0)
            continue;
        if (virNetSocketAddIOCallback(socks[i],
                                      VIR_EVENT_HANDLE_READABLE,
                                      lxcMigrateReceive,
                                      args,
                                      virObjectFreeCallback) < 0)
            continue;

        /*
         * Successfully added sock to event loop.  Take a ref on args to
         * ensure it is not freed until sock is removed from the event loop.
         * Ref is dropped in virObjectFreeCallback after being removed
         * from the event loop.
         */
        virObjectRef(args);
        nsocks_listen++;
    }

    /* Done with args in this function, drop reference */
    virObjectUnref(args);

    if (!nsocks_listen)
        goto cleanup;

    ret = 0;
    goto done;

 cleanup:
    for (i = 0; i < nsocks; i++) {
        virNetSocketClose(socks[i]);
        virObjectUnref(socks[i]);
    }

 done:
    virURIFree(uri);
    virDomainObjEndAPI(&vm);
    return ret;
}

int
lxcDomainMigrationPerform(virLXCDriverPtr driver,
                          virDomainObjPtr vm,
                          const char *dom_xml ATTRIBUTE_UNUSED,
                          const char *dconnuri ATTRIBUTE_UNUSED,
                          const char *uri_str,
                          const char *dname ATTRIBUTE_UNUSED,
                          unsigned int flags)
{
    char *hostname = NULL;
    unsigned short port = 0;
    char portstr[100];
    virURIPtr uri = NULL;
    virNetSocketPtr sock;
    int sockfd = -1;
    int saved_errno = EINVAL;
    int ret = -1;

    if (!(flags & VIR_MIGRATE_LIVE)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       "%s", _("Offline migration not supported"));
        goto cleanup;
    }

    /* parse dst host:port from uri */
    uri = virURIParse(uri_str);
    if (uri == NULL || uri->server == NULL || uri->port == 0)
        goto cleanup;

    hostname = uri->server;
    port = uri->port;
    snprintf(portstr, sizeof(portstr), "%d", port);

    /* socket connect to dst host:port */
    if (virNetSocketNewConnectTCP(hostname, portstr,
                                  AF_UNSPEC, &sock) < 0) {
        virReportSystemError(saved_errno,
                             _("unable to connect to '%s:%s'"),
                             hostname, portstr);
        goto cleanup;
    }

    if (virNetSocketSetBlocking(sock, true) < 0) {
        virObjectUnref(sock);
        goto cleanup;
    }

    sockfd = virNetSocketDupFD(sock, true);
    virObjectUnref(sock);

    /* checkpoint container and send saved data to dst through socket fd */
    virObjectUnlock(vm);
    ret = lxcDoMigrateSend(driver, vm, sockfd);
    virObjectLock(vm);

 cleanup:
    /* If failure, terminate the job started in MigrationBegin */
    if (ret == -1) {
        virLXCDomainObjEndJob(driver, vm);
        virDomainObjEndAPI(&vm);
    }
    VIR_FORCE_CLOSE(sockfd);
    virURIFree(uri);
    return ret;
}

virDomainPtr
lxcDomainMigrationFinish(virConnectPtr dconn,
                         virDomainObjPtr vm,
                         unsigned int flags,
                         int cancelled)
{
    virLXCDriverPtr driver = dconn->privateData;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainPtr dom = NULL;
    virCapsPtr caps = NULL;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    virPortAllocatorRelease(priv->migrationPort);
    priv->migrationPort = 0;

    if (cancelled)
        goto cleanup;

    /* Check if domain is alive */
    if (!virDomainObjIsActive(vm)) {
        /* Migration failed if domain is inactive*/
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("Migration failed. Domain is not running "
                               "on destination host"));
        goto cleanup;
    }

    if (!(flags & VIR_MIGRATE_PAUSED)) {
        /*Unfreeze domain*/
    }


    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto cleanup;

    dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    if (dom == NULL) {
        /*Cleanup domain*/
    }
    virObjectUnref(cfg);
    return dom;
}

int
lxcDomainMigrationConfirm(virLXCDriverPtr driver,
                          virDomainObjPtr vm,
                          unsigned int flags,
                          int cancelled)
{
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (cancelled) {
        /*Must restore the domain on the source host*/
        goto cleanup;
    }

    /*virDomainDestroy(dom);*/
    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_MIGRATED);

    if (flags & VIR_MIGRATE_UNDEFINE_SOURCE)
        virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);

    if (!vm->persistent || (flags & VIR_MIGRATE_UNDEFINE_SOURCE)) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }
    ret = 0;

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}
