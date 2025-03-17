
#include "Handlers/Dpdk/Errno.h"

#include <cerrno>
#include <cstdlib>

std::string_view Nta::Network::GetDpdkErrorMessage(const int err) {
    if (auto code = std::abs(err); code == EPERM)
        return std::string_view{"Operation not permitted"};
    else if (code == ENOENT)
        return std::string_view{"No such file or directory"};
    else if (code == ESRCH)
        return std::string_view{"No such process"};
    else if (code == EINTR)
        return std::string_view{"Interrupted system call"};
    else if (code == EIO)
        return std::string_view{"I/O error"};
    else if (code == ENXIO)
        return std::string_view{"No such device or address"};
    else if (code == E2BIG)
        return std::string_view{"Argument list too long"};
    else if (code == ENOEXEC)
        return std::string_view{"Exec format error"};
    else if (code == EBADF)
        return std::string_view{"Bad file number"};
    else if (code == ECHILD)
        return std::string_view{"No child processes"};
    else if (code == EAGAIN)
        return std::string_view{"Try again"};
    else if (code == ENOMEM)
        return std::string_view{"Out of memory"};
    else if (code == EACCES)
        return std::string_view{"Permission denied"};
    else if (code == EFAULT)
        return std::string_view{"Bad address"};
    else if (code == ENOTBLK)
        return std::string_view{"Block device required"};
    else if (code == EBUSY)
        return std::string_view{"Device or resource busy"};
    else if (code == EEXIST)
        return std::string_view{"File exists"};
    else if (code == EXDEV)
        return std::string_view{"Cross-device link"};
    else if (code == ENODEV)
        return std::string_view{"No such device"};
    else if (code == ENOTDIR)
        return std::string_view{"Not a directory"};
    else if (code == EISDIR)
        return std::string_view{"Is a directory"};
    else if (code == EINVAL)
        return std::string_view{"Invalid argument"};
    else if (code == ENFILE)
        return std::string_view{"File table overflow"};
    else if (code == EMFILE)
        return std::string_view{"Too many open files"};
    else if (code == ENOTTY)
        return std::string_view{"Not a typewriter"};
    else if (code == ETXTBSY)
        return std::string_view{"Text file busy"};
    else if (code == EFBIG)
        return std::string_view{"File too large"};
    else if (code == ENOSPC)
        return std::string_view{"No space left on device"};
    else if (code == ESPIPE)
        return std::string_view{"Illegal seek"};
    else if (code == EROFS)
        return std::string_view{"Read-only file system"};
    else if (code == EMLINK)
        return std::string_view{"Too many links"};
    else if (code == EPIPE)
        return std::string_view{"Broken pipe"};
    else if (code == EDOM)
        return std::string_view{"Math argument out of domain of func"};
    else if (code == ERANGE)
        return std::string_view{"Math result not representable"};
    else
        return std::string_view{"Unknow error code"};
}
