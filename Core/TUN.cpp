#include "TUN.hpp"

#include <cstring>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

int TunAlloc(const std::string &interface_name)
{
    int descriptor = open("/dev/net/tun",
                          O_RDWR | O_CLOEXEC);

    if (descriptor < 0)
    {
        std::cerr << "Error in open /dev/net/tun\n";
        return -1;
    }

    struct ifreq request {};
    request.ifr_flags = IFF_TUN | IFF_NO_PI;

    std::strncpy(request.ifr_name,
                 interface_name.c_str(),
                 IFNAMSIZ);

    if (ioctl(descriptor, TUNSETIFF,
              (void *)&request) < 0)
    {
        std::cerr << "Error in ioctl TUNSETIFF\n";
        close(descriptor);
        return -1;
    }

    std::cout << "TUN up: " << request.ifr_name << "\n";
    return descriptor;
}
