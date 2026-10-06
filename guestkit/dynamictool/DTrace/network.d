#!/usr/sbin/dtrace -C -s

#pragma D option quiet

inline int AF_UNIX   = 1;
inline int AF_INET   = 2;
inline int AF_INET6  = 30;

#define NOISE_FILTER \
    execname != "mDNSResponder" && \
    execname != "oahd" && \
    execname != "configd" && \
    execname != "syslogd" && \
    execname != "logd" && \
    execname != "logd_helper" && \
    execname != "xpcproxy" && \
    execname != "distnoted" && \
    execname != "launchd" && \
    execname != "notifyd" && \
    execname != "timed" && \
    execname != "airportd" && \
    execname != "WindowServer" && \
    execname != "kernel_task" && \
    execname != "mds" && \
    execname != "mdworker" && \
    execname != "mdworker_shared" && \
    execname != "coreservicesd" && \
    execname != "cfprefsd" && \
    execname != "secd" && \
    execname != "cloudd" && \
    execname != "accountsd" && \
    execname != "biomed" && \
    execname != "sandboxd" && \
    execname != "symptomsd" && \
    execname != "trustd" && \
    execname != "tccd" && \
    execname != "powerd" && \
    execname != "thermalmonitord" && \
    execname != "runningboardd" 

BEGIN {
    printf("PROBE_START\n");
}

/* ---------- socket create ---------- */
syscall::socket:entry
/NOISE_FILTER/
{
    this->domain = arg0;
    this->socktype = arg1;
    this->proto = arg2;

    if (this->domain == AF_INET) {
        printf("ts=%lld type=dnet_socket pid=%d comm=%s family=inet4 socktype=%d protocol=%d dir=create\n", walltimestamp / 1000000000, pid, execname, this->socktype, this->proto);
    }
    else if (this->domain == AF_INET6) {
        printf("ts=%lld type=dnet_socket pid=%d comm=%s family=inet6 socktype=%d protocol=%d dir=create\n", walltimestamp / 1000000000, pid, execname, this->socktype, this->proto);
    }
    else if (this->domain == AF_UNIX) {
        printf("ts=%lld type=dnet_socket pid=%d comm=%s family=unix socktype=%d protocol=%d dir=create\n", walltimestamp / 1000000000, pid, execname, this->socktype, this->proto);
    }
}

/* ---------- TCP/UDP connect ---------- */
syscall::connect:entry,
syscall::connect_nocancel:entry
/arg1 != 0 && NOISE_FILTER/
{
    this->sa = (uint8_t *)copyin(arg1, 128);
    this->family = this->sa[1];

    if (this->family == AF_INET) {
        this->sin = (struct sockaddr_in *)this->sa;
        this->port = ntohs(this->sin->sin_port);
        this->a = (uint8_t)((this->sin->sin_addr.s_addr >>  0) & 0xff);
        this->b = (uint8_t)((this->sin->sin_addr.s_addr >>  8) & 0xff);
        this->c = (uint8_t)((this->sin->sin_addr.s_addr >> 16) & 0xff);
        this->d = (uint8_t)((this->sin->sin_addr.s_addr >> 24) & 0xff);
        printf("ts=%lld type=dnet_tcp_connect pid=%d comm=%s family=inet4 remote=%u.%u.%u.%u:%d dir=outbound\n", walltimestamp / 1000000000, pid, execname, this->a, this->b, this->c, this->d, this->port);
    }
    else if (this->family == AF_INET6) {
        this->sin6 = (struct sockaddr_in6 *)this->sa;
        this->port = ntohs(this->sin6->sin6_port);
        this->p = (uint16_t *)this->sin6->sin6_addr.__u6_addr.__u6_addr16;
        printf("ts=%lld type=dnet_tcp_connect pid=%d comm=%s family=inet6 remote=[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d dir=outbound\n", walltimestamp / 1000000000, pid, execname, ntohs(this->p[0]), ntohs(this->p[1]), ntohs(this->p[2]), ntohs(this->p[3]), ntohs(this->p[4]), ntohs(this->p[5]), ntohs(this->p[6]), ntohs(this->p[7]), this->port);
    }
    else if (this->family == AF_UNIX) {
        this->path = (char *)copyin((uintptr_t)arg1 + 2, 104);
        printf("ts=%lld type=dnet_unix_connect pid=%d comm=%s family=unix path=%s dir=outbound\n", walltimestamp / 1000000000, pid, execname, stringof(this->path));
    }
}

/* ---------- bind ---------- */
syscall::bind:entry
/arg1 != 0 && arg2 > 0 && NOISE_FILTER/
{
    this->len = arg2 <= 128 ? arg2 : 128;
    this->sa = (uint8_t *)copyin(arg1, this->len);
    this->family = this->sa[1];

    if (this->family == AF_INET) {
        this->sin = (struct sockaddr_in *)this->sa;
        this->port = ntohs(this->sin->sin_port);
        this->a = (uint8_t)((this->sin->sin_addr.s_addr >>  0) & 0xff);
        this->b = (uint8_t)((this->sin->sin_addr.s_addr >>  8) & 0xff);
        this->c = (uint8_t)((this->sin->sin_addr.s_addr >> 16) & 0xff);
        this->d = (uint8_t)((this->sin->sin_addr.s_addr >> 24) & 0xff);
        printf("ts=%lld type=dnet_bind pid=%d comm=%s family=inet4 local=%u.%u.%u.%u:%d dir=bind\n", walltimestamp / 1000000000, pid, execname, this->a, this->b, this->c, this->d, this->port);
    }
    else if (this->family == AF_INET6) {
        this->sin6 = (struct sockaddr_in6 *)this->sa;
        this->port = ntohs(this->sin6->sin6_port);
        this->p = (uint16_t *)this->sin6->sin6_addr.__u6_addr.__u6_addr16;
        printf("ts=%lld type=dnet_bind pid=%d comm=%s family=inet6 local=[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d dir=bind\n", walltimestamp / 1000000000, pid, execname, ntohs(this->p[0]), ntohs(this->p[1]), ntohs(this->p[2]), ntohs(this->p[3]), ntohs(this->p[4]), ntohs(this->p[5]), ntohs(this->p[6]), ntohs(this->p[7]), this->port);
    }
    else if (this->family == AF_UNIX) {
        this->path = (char *)copyin((uintptr_t)arg1 + 2, 104);
        printf("ts=%lld type=dnet_bind pid=%d comm=%s family=unix path=%s dir=bind\n", walltimestamp / 1000000000, pid, execname, stringof(this->path));
    }
}

/* ---------- TCP accept ---------- */
syscall::accept:entry,
syscall::accept_nocancel:entry
/arg1 != 0 && arg2 != 0 && NOISE_FILTER/
{
    self->accept_sa   = arg1;
    self->accept_lenp = arg2;
}

syscall::accept:return,
syscall::accept_nocancel:return
/arg0 >= 0 && self->accept_sa != 0 && self->accept_lenp != 0/
{
    this->len = *(socklen_t *)copyin(self->accept_lenp, sizeof(socklen_t));
    if (this->len > 0 && this->len <= 128) {
        this->sa = (uint8_t *)copyin(self->accept_sa, this->len);
        this->family = this->sa[1];

        if (this->family == AF_INET) {
            this->sin = (struct sockaddr_in *)this->sa;
            this->port = ntohs(this->sin->sin_port);
            this->a = (uint8_t)((this->sin->sin_addr.s_addr >>  0) & 0xff);
            this->b = (uint8_t)((this->sin->sin_addr.s_addr >>  8) & 0xff);
            this->c = (uint8_t)((this->sin->sin_addr.s_addr >> 16) & 0xff);
            this->d = (uint8_t)((this->sin->sin_addr.s_addr >> 24) & 0xff);
            printf("ts=%lld type=dnet_tcp_accept pid=%d comm=%s family=inet4 remote=%u.%u.%u.%u:%d dir=inbound\n", walltimestamp / 1000000000, pid, execname, this->a, this->b, this->c, this->d, this->port);
        }
        else if (this->family == AF_INET6) {
            this->sin6 = (struct sockaddr_in6 *)this->sa;
            this->port = ntohs(this->sin6->sin6_port);
            this->p = (uint16_t *)this->sin6->sin6_addr.__u6_addr.__u6_addr16;
            printf("ts=%lld type=dnet_tcp_accept pid=%d comm=%s family=inet6 remote=[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d dir=inbound\n", walltimestamp / 1000000000, pid, execname, ntohs(this->p[0]), ntohs(this->p[1]), ntohs(this->p[2]), ntohs(this->p[3]), ntohs(this->p[4]), ntohs(this->p[5]), ntohs(this->p[6]), ntohs(this->p[7]), this->port);
        }
        else if (this->family == AF_UNIX) {
            this->path = (char *)copyin(self->accept_sa + 2, 104);
            printf("ts=%lld type=dnet_unix_accept pid=%d comm=%s family=unix path=%s dir=inbound\n", walltimestamp / 1000000000, pid, execname, stringof(this->path));
        }
    }
    self->accept_sa   = 0;
    self->accept_lenp = 0;
}

/* ---------- UDP sendto ---------- */
syscall::sendto:entry
/arg4 != 0 && NOISE_FILTER/
{
    this->sa = (uint8_t *)copyin(arg4, 128);
    this->family = this->sa[1];

    if (this->family == AF_INET) {
        this->sin = (struct sockaddr_in *)this->sa;
        this->port = ntohs(this->sin->sin_port);
        this->a = (uint8_t)((this->sin->sin_addr.s_addr >>  0) & 0xff);
        this->b = (uint8_t)((this->sin->sin_addr.s_addr >>  8) & 0xff);
        this->c = (uint8_t)((this->sin->sin_addr.s_addr >> 16) & 0xff);
        this->d = (uint8_t)((this->sin->sin_addr.s_addr >> 24) & 0xff);
        printf("ts=%lld type=dnet_udp_send pid=%d comm=%s family=inet4 remote=%u.%u.%u.%u:%d dir=outbound\n", walltimestamp / 1000000000, pid, execname, this->a, this->b, this->c, this->d, this->port);
    }
    else if (this->family == AF_INET6) {
        this->sin6 = (struct sockaddr_in6 *)this->sa;
        this->port = ntohs(this->sin6->sin6_port);
        this->p = (uint16_t *)this->sin6->sin6_addr.__u6_addr.__u6_addr16;
        printf("ts=%lld type=dnet_udp_send pid=%d comm=%s family=inet6 remote=[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d dir=outbound\n", walltimestamp / 1000000000, pid, execname, ntohs(this->p[0]), ntohs(this->p[1]), ntohs(this->p[2]), ntohs(this->p[3]), ntohs(this->p[4]), ntohs(this->p[5]), ntohs(this->p[6]), ntohs(this->p[7]), this->port);
    }
}

/* ---------- UDP recvfrom ---------- */
syscall::recvfrom:entry
/arg4 != 0 && arg5 != 0 && NOISE_FILTER/
{
    self->recvfrom_sa   = arg4;
    self->recvfrom_lenp = arg5;
}

syscall::recvfrom:return
/arg0 >= 0 && self->recvfrom_sa != 0 && self->recvfrom_lenp != 0/
{
    this->len = *(socklen_t *)copyin(self->recvfrom_lenp, sizeof(socklen_t));
    if (this->len > 0 && this->len <= 128) {
        this->sa = (uint8_t *)copyin(self->recvfrom_sa, this->len);
        this->family = this->sa[1];

        if (this->family == AF_INET) {
            this->sin = (struct sockaddr_in *)this->sa;
            this->port = ntohs(this->sin->sin_port);
            this->a = (uint8_t)((this->sin->sin_addr.s_addr >>  0) & 0xff);
            this->b = (uint8_t)((this->sin->sin_addr.s_addr >>  8) & 0xff);
            this->c = (uint8_t)((this->sin->sin_addr.s_addr >> 16) & 0xff);
            this->d = (uint8_t)((this->sin->sin_addr.s_addr >> 24) & 0xff);
            printf("ts=%lld type=dnet_udp_recv pid=%d comm=%s family=inet4 remote=%u.%u.%u.%u:%d dir=inbound\n", walltimestamp / 1000000000, pid, execname, this->a, this->b, this->c, this->d, this->port);
        }
        else if (this->family == AF_INET6) {
            this->sin6 = (struct sockaddr_in6 *)this->sa;
            this->port = ntohs(this->sin6->sin6_port);
            this->p = (uint16_t *)this->sin6->sin6_addr.__u6_addr.__u6_addr16;
            printf("ts=%lld type=dnet_udp_recv pid=%d comm=%s family=inet6 remote=[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d dir=inbound\n", walltimestamp / 1000000000, pid, execname, ntohs(this->p[0]), ntohs(this->p[1]), ntohs(this->p[2]), ntohs(this->p[3]), ntohs(this->p[4]), ntohs(this->p[5]), ntohs(this->p[6]), ntohs(this->p[7]), this->port);
        }
    }
    self->recvfrom_sa   = 0;
    self->recvfrom_lenp = 0;
}

/* ---------- sendmsg ---------- */
syscall::sendmsg:entry
/arg1 != 0 && NOISE_FILTER/
{
    this->msghdr = (struct msghdr *)copyin(arg1, sizeof(struct msghdr));
    this->sa = (uint8_t *)this->msghdr->msg_name;
    if (this->sa != NULL) {
        this->sa_copy = (uint8_t *)copyin((uintptr_t)this->sa, 128);
        this->family = this->sa_copy[1];

        if (this->family == AF_INET) {
            this->sin = (struct sockaddr_in *)this->sa_copy;
            this->port = ntohs(this->sin->sin_port);
            this->a = (uint8_t)((this->sin->sin_addr.s_addr >>  0) & 0xff);
            this->b = (uint8_t)((this->sin->sin_addr.s_addr >>  8) & 0xff);
            this->c = (uint8_t)((this->sin->sin_addr.s_addr >> 16) & 0xff);
            this->d = (uint8_t)((this->sin->sin_addr.s_addr >> 24) & 0xff);
            printf("ts=%lld type=dnet_msg_send pid=%d comm=%s family=inet4 remote=%u.%u.%u.%u:%d dir=outbound\n", walltimestamp / 1000000000, pid, execname, this->a, this->b, this->c, this->d, this->port);
        }
        else if (this->family == AF_INET6) {
            this->sin6 = (struct sockaddr_in6 *)this->sa_copy;
            this->port = ntohs(this->sin6->sin6_port);
            this->p = (uint16_t *)this->sin6->sin6_addr.__u6_addr.__u6_addr16;
            printf("ts=%lld type=dnet_msg_send pid=%d comm=%s family=inet6 remote=[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d dir=outbound\n", walltimestamp / 1000000000, pid, execname, ntohs(this->p[0]), ntohs(this->p[1]), ntohs(this->p[2]), ntohs(this->p[3]), ntohs(this->p[4]), ntohs(this->p[5]), ntohs(this->p[6]), ntohs(this->p[7]), this->port);
        }
    }
}

/* ---------- recvmsg ---------- */
syscall::recvmsg:entry
/arg1 != 0 && NOISE_FILTER/
{
    self->recvmsg_msghdr = arg1;
}

syscall::recvmsg:return
/arg0 >= 0 && self->recvmsg_msghdr != 0/
{
    this->msghdr = (struct msghdr *)copyin(self->recvmsg_msghdr, sizeof(struct msghdr));
    this->sa = (uint8_t *)this->msghdr->msg_name;
    if (this->sa != NULL) {
        this->sa_copy = (uint8_t *)copyin((uintptr_t)this->sa, 128);
        this->family = this->sa_copy[1];

        if (this->family == AF_INET) {
            this->sin = (struct sockaddr_in *)this->sa_copy;
            this->port = ntohs(this->sin->sin_port);
            this->a = (uint8_t)((this->sin->sin_addr.s_addr >>  0) & 0xff);
            this->b = (uint8_t)((this->sin->sin_addr.s_addr >>  8) & 0xff);
            this->c = (uint8_t)((this->sin->sin_addr.s_addr >> 16) & 0xff);
            this->d = (uint8_t)((this->sin->sin_addr.s_addr >> 24) & 0xff);
            printf("ts=%lld type=dnet_msg_recv pid=%d comm=%s family=inet4 remote=%u.%u.%u.%u:%d dir=inbound\n", walltimestamp / 1000000000, pid, execname, this->a, this->b, this->c, this->d, this->port);
        }
        else if (this->family == AF_INET6) {
            this->sin6 = (struct sockaddr_in6 *)this->sa_copy;
            this->port = ntohs(this->sin6->sin6_port);
            this->p = (uint16_t *)this->sin6->sin6_addr.__u6_addr.__u6_addr16;
            printf("ts=%lld type=dnet_msg_recv pid=%d comm=%s family=inet6 remote=[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d dir=inbound\n", walltimestamp / 1000000000, pid, execname, ntohs(this->p[0]), ntohs(this->p[1]), ntohs(this->p[2]), ntohs(this->p[3]), ntohs(this->p[4]), ntohs(this->p[5]), ntohs(this->p[6]), ntohs(this->p[7]), this->port);
        }
    }
    self->recvmsg_msghdr = 0;
}
