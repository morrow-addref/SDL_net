#ifdef _WIN32
#ifdef _WIN32_WINNT
#if _WIN32_WINNT < 0x0600 // we need APIs that didn't arrive until Windows Vista.
#undef _WIN32_WINNT
#endif
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#endif /* _WIN32 */

#include "SDL3_net/SDL_net_extended.h"
#include "SDL3_net/SDL_net.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET Socket;
typedef int SockLen;
typedef SOCKADDR_STORAGE AddressStorage;
#define poll WSAPoll
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
typedef int Socket;
typedef socklen_t SockLen;
typedef struct sockaddr_storage AddressStorage;
#endif

typedef enum NET_Status
{
    NET_FAILURE = -1,
    NET_WOULDBLOCK,
    NET_SUCCESS,
} NET_Status;

typedef enum NET_SocketType
{
    SOCKETTYPE_STREAM,
    SOCKETTYPE_DATAGRAM,
    SOCKETTYPE_SERVER
} NET_SocketType;

struct NET_Address
{
    char *hostname;
    char *human_readable;
    char *errstr;
    SDL_AtomicInt refcount;
    SDL_AtomicInt status;       // 0==in progress, 1==resolved, -1==error
    struct addrinfo *ainfo;
    NET_Address *resolver_next; // a linked list for the resolution job queue.
};

#define MIN_RESOLVER_THREADS 2
#define MAX_RESOLVER_THREADS 10

static NET_Address *resolver_queue = NULL;
static SDL_Thread *resolver_threads[MAX_RESOLVER_THREADS];
static SDL_Mutex *resolver_lock = NULL;
static SDL_Condition *resolver_condition = NULL;
static SDL_AtomicInt resolver_shutdown;
static SDL_AtomicInt resolver_num_threads;
static SDL_AtomicInt resolver_num_requests;
static SDL_AtomicInt resolver_percent_loss;

static int random_seed = 0;
static int RandomNumber(void)
{
    // this is POSIX.1-2001's potentially bad suggestion, but we're not exactly doing cryptography here.
    random_seed = random_seed * 1103515245 + 12345;
    return (int)((unsigned int)(random_seed / 65536) % 32768);
}

// between lo and hi (inclusive; it can return lo or hi itself, too!).
static int RandomNumberBetween(const int lo, const int hi)
{
    return (RandomNumber() % (hi + 1 - lo)) + lo;
}

static char *CreateSocketErrorString(int rc)
{
#ifdef _WIN32
    WCHAR msgbuf[256];
    const DWORD bw = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        rc,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
        msgbuf,
        SDL_arraysize(msgbuf),
        NULL);
    if (bw == 0)
    {
        return SDL_strdup("Unknown error");
    }
    return SDL_iconv_string("UTF-8", "UTF-16LE", (const char *)msgbuf, (((size_t)bw) + 1) * sizeof(WCHAR));
#else
    return SDL_strdup(strerror(rc));
#endif
}

static char *CreateGetAddrInfoErrorString(int rc)
{
#ifdef _WIN32
    return CreateSocketErrorString(rc); // same error codes.
#else
    return SDL_strdup((rc == EAI_SYSTEM) ? strerror(errno) : gai_strerror(rc));
#endif
}

// this blocks!
static NET_Status ResolveAddress(NET_Address *addr)
{
    SDL_assert(addr != NULL); // we control all this, so this shouldn't happen.
    struct addrinfo *ainfo = NULL;
    int rc;

    // SDL_Log("getaddrinfo '%s'", addr->hostname);
    rc = getaddrinfo(addr->hostname, NULL, addr->ainfo, &ainfo);
    // SDL_Log("rc=%d", rc);
    if (rc != 0)
    {
        addr->errstr = CreateGetAddrInfoErrorString(rc);
        return NET_FAILURE; // error
    }
    else if (ainfo == NULL)
    {
        addr->errstr = SDL_strdup("Unknown error (query succeeded but result was NULL!)");
        return NET_FAILURE;
    }

    if (addr->ainfo != NULL)
    {
        SDL_free(addr->ainfo);
    }

    char buf[128];
    rc = getnameinfo(ainfo->ai_addr, ainfo->ai_addrlen, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
    if (rc != 0)
    {
        addr->errstr = CreateGetAddrInfoErrorString(rc);
        freeaddrinfo(ainfo);
        return NET_FAILURE; // error
    }

    addr->human_readable = SDL_strdup(buf);
    addr->ainfo = ainfo;
    return NET_SUCCESS; // success (zero means "still in progress").
}

static int SDLCALL ResolverThread(void *data)
{
    const int threadnum = (int)((intptr_t)data);
    // SDL_Log("ResolverThread #%d starting up!", threadnum);

    SDL_LockMutex(resolver_lock);

    while (!SDL_GetAtomicInt(&resolver_shutdown))
    {
        NET_Address *addr = SDL_GetAtomicPointer((void **)&resolver_queue);
        if (!addr)
        {
            if (SDL_GetAtomicInt(&resolver_num_threads) > MIN_RESOLVER_THREADS)
            {                                                  // nothing pending and too many threads waiting in reserve? Quit.
                SDL_DetachThread(resolver_threads[threadnum]); // detach ourselves so no one has to wait on us.
                SDL_SetAtomicPointer((void **)&resolver_threads[threadnum], NULL);
                break;                                         // we quit. They'll spawn new threads if necessary.
            }

            // Block until there's something to do.
            SDL_WaitCondition(resolver_condition, resolver_lock);            // surrenders the lock, sleeps until alerted, then relocks.
            continue;                                                        // check for shutdown and new work again!
        }

        SDL_SetAtomicPointer((void **)&resolver_queue, addr->resolver_next); // take this task off the list, then release the lock so others can work.
        SDL_UnlockMutex(resolver_lock);

        // SDL_Log("ResolverThread #%d got new task ('%s')", threadnum, addr->hostname);

        const int simulated_loss = SDL_GetAtomicInt(&resolver_percent_loss);

        if (simulated_loss && (RandomNumberBetween(0, 100) > simulated_loss))
        {
            // won the percent_loss lottery? Delay resolving this address between 250 and 7000 milliseconds
            SDL_Delay(RandomNumberBetween(250, 2000 + (50 * simulated_loss)));
        }

        int outcome;
        if (!simulated_loss || (RandomNumberBetween(0, 100) > simulated_loss))
        {
            outcome = ResolveAddress(addr);
        }
        else
        {
            outcome = -1;
            addr->errstr = SDL_strdup("simulated failure");
        }

        SDL_SetAtomicInt(&addr->status, outcome);
        // SDL_Log("ResolverThread #%d finished current task (%s, '%s' => '%s')", threadnum, (outcome < 0) ? "failure" : "success", addr->hostname, (outcome < 0) ? addr->errstr : addr->human_readable);

        NET_UnrefAddress(addr); // we're done with it, but others might still own it.

        SDL_AddAtomicInt(&resolver_num_requests, -1);

        // okay, we're done with this task, grab the lock so we can see what's next.
        SDL_LockMutex(resolver_lock);
        SDL_BroadcastCondition(resolver_condition); // wake up anything waiting on results, and also give all resolver threads a chance to see if they are still needed.
    }

    SDL_AddAtomicInt(&resolver_num_threads, -1);
    SDL_UnlockMutex(resolver_lock); // we're quitting, let go of the lock.

    // SDL_Log("ResolverThread #%d ending!", threadnum);
    return 0;
}

static SDL_Thread *SpinResolverThread(const int num)
{
    char name[16];
    SDL_snprintf(name, sizeof(name), "SDLNetRslv%d", num);
    SDL_assert(resolver_threads[num] == NULL);
    SDL_AddAtomicInt(&resolver_num_threads, 1);
    const SDL_PropertiesID props = SDL_CreateProperties();
    SDL_SetPointerProperty(props, SDL_PROP_THREAD_CREATE_ENTRY_FUNCTION_POINTER, (void *)ResolverThread);
    SDL_SetStringProperty(props, SDL_PROP_THREAD_CREATE_NAME_STRING, name);
    SDL_SetPointerProperty(props, SDL_PROP_THREAD_CREATE_USERDATA_POINTER, (void *)((intptr_t)num));
    SDL_SetNumberProperty(props, SDL_PROP_THREAD_CREATE_STACKSIZE_NUMBER, 64 * 1024);
    resolver_threads[num] = SDL_CreateThreadWithProperties(props);
    SDL_DestroyProperties(props);
    if (!resolver_threads[num])
    {
        SDL_AddAtomicInt(&resolver_num_threads, -1);
    }
    return resolver_threads[num];
}

NET_Address *NETEx_ResolveHostname(const char *host, NETEx_ResolveAddressFlags flags)
{
    NET_Address *addr = SDL_calloc(1, sizeof(NET_Address));
    if (!addr)
    {
        return NULL;
    }

    switch (flags)
    {
    case NETEx_Any:
        addr->ainfo = NULL;
        // Carry on
        break;
    case NETEx_IPv4:
        addr->ainfo = SDL_calloc(1, sizeof(*addr->ainfo));
        addr->ainfo->ai_family = AF_INET;
        break;
    case NETEx_IPv6:
        addr->ainfo = SDL_calloc(1, sizeof(*addr->ainfo));
        addr->ainfo->ai_family = AF_INET6;
        break;
    }

    addr->hostname = SDL_strdup(host);
    if (!addr->hostname)
    {
        SDL_free(addr);
        return NULL;
    }

    SDL_SetAtomicInt(&addr->refcount, 2); // one for creation, one for the resolver thread to unref when done.

    SDL_LockMutex(resolver_lock);

    // !!! FIXME: this should append to the list, not prepend; as is, new requests will make existing pending requests take longer to start processing.
    SDL_SetAtomicPointer((void **)&addr->resolver_next, SDL_GetAtomicPointer((void **)&resolver_queue));
    SDL_SetAtomicPointer((void **)&resolver_queue, addr);

    const int num_threads = SDL_GetAtomicInt(&resolver_num_threads);
    const int num_requests = SDL_AddAtomicInt(&resolver_num_requests, 1) + 1;
    // SDL_Log("num_threads=%d, num_requests=%d", num_threads, num_requests);
    if ((num_requests >= num_threads) && (num_threads < MAX_RESOLVER_THREADS))
    { // all threads are busy? Maybe spawn a new one.
        // if this didn't actually spin one up, it is what it is...the existing threads will eventually get there.
        for (int i = 0; i < ((int)SDL_arraysize(resolver_threads)); i++)
        {
            if (!resolver_threads[i])
            {
                SpinResolverThread(i);
                break;
            }
        }
    }

    SDL_SignalCondition(resolver_condition);
    SDL_UnlockMutex(resolver_lock);

    return addr;
}
