#include "internet/scan_client/scan_dir_impl.hpp"

namespace internet
{

    namespace service
    {
								
                void scan_dir_impl::read_msg_scan() {
                    LOG(INFO)<<" Read message scan ";
                }

                void scan_dir_impl::add_directory(const std::string dir_name) {
                    LOG(INFO)<<" Add directory : " << dir_name;
                }

								void scan_dir_impl::destory(){ LOG(INFO)<<" Destory "; } 

    }

}
