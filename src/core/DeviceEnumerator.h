#pragma once
#include "Types.h"

namespace dd {

std::vector<DeviceInfo> enumerateDevices();
DeviceInfo describePath(const std::string &path);
void probeReadable(DeviceInfo &dev);

} // namespace dd
