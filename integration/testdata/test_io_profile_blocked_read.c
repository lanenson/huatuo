// Copyright 2026 The HuaTuo Authors.
// SPDX-License-Identifier: Apache-2.0

/* Hold a buffered file read in its userspace copy until the test releases it. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct blocked_read {
	int uffd;
	struct uffdio_range range;
};

int io_profile_fault_support(void)
{
	int uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);

	if (uffd < 0)
		return -errno;
	close(uffd);
	return 0;
}

static void *release_fault(void *arg)
{
	struct blocked_read *blocked = arg;
	struct pollfd fault = {.fd = blocked->uffd, .events = POLLIN};
	struct uffdio_zeropage page = {.range = blocked->range};
	struct pollfd release = {.fd = STDIN_FILENO, .events = POLLIN};
	struct uffd_msg message;
	struct timespec now;
	char token;

	if (poll(&fault, 1, 10000) != 1 ||
	    read(fault.fd, &message, sizeof(message)) != sizeof(message) ||
	    message.event != UFFD_EVENT_PAGEFAULT ||
	    clock_gettime(CLOCK_REALTIME, &now) != 0) {
		fputs("no user page fault from the fixture read\n", stderr);
		_exit(1);
	}
	dprintf(STDOUT_FILENO, "io-cutoff-blocked %lld%09ld\n",
		(long long)now.tv_sec, now.tv_nsec);
	if (poll(&release, 1, 10000) != 1 || read(release.fd, &token, 1) != 1 ||
	    ioctl(blocked->uffd, UFFDIO_ZEROPAGE, &page) != 0) {
		fputs("could not release the blocked fixture read\n", stderr);
		_exit(1);
	}
	return NULL;
}

int io_profile_blocked_read(int fd)
{
	struct uffdio_api api = {.api = UFFD_API};
	struct blocked_read blocked;
	struct uffdio_register registration;
	pthread_t worker;
	long size = sysconf(_SC_PAGESIZE);
	void *address;
	int result;

	if (size < 3072)
		return -EINVAL;
	address = mmap(NULL, size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (address == MAP_FAILED)
		return -errno;
	blocked.uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (blocked.uffd < 0) {
		result = -errno;
		goto unmap;
	}
	blocked.range.start = (unsigned long)address;
	blocked.range.len = size;
	registration = (struct uffdio_register){
		.range = blocked.range,
		.mode = UFFDIO_REGISTER_MODE_MISSING,
	};
	if (ioctl(blocked.uffd, UFFDIO_API, &api) != 0 ||
	    ioctl(blocked.uffd, UFFDIO_REGISTER, &registration) != 0) {
		result = -errno;
		goto close;
	}
	result = -pthread_create(&worker, NULL, release_fault, &blocked);
	if (result != 0)
		goto close;

	result = pread(fd, address, 3072, 0);
	if (result < 0)
		result = -errno;
	pthread_join(worker, NULL);
close:
	close(blocked.uffd);
unmap:
	munmap(address, size);
	return result;
}
