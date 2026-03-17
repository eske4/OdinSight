#pragma once

namespace HealthChecker
{

    struct HealthStatus
    {
        bool secureBootEnabled;
    };

    bool isSecureBootEnabled();
    HealthStatus performHealthCheck();
    void printHealthStatus();

}
