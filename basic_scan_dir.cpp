#include "internet/scan_client/basic_scan_dir.hpp"

namespace internet
{

    namespace service
    {

        template<typename Service>
        void basic_scan_dir<Service>::add_directory(const std::string& dir_name)
        {
            this->service.add_directory(this->implementation, dir_name);
        }

				template class basic_scan_dir<basic_scan_dir_service<> >;

    }

}
