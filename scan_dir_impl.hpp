#ifndef INTERNET_SERVICE_SCAN_DIR_IMPL_HPP
#define INTERNET_SERVICE_SCAN_DIR_IMPL_HPP

/*
* Copyright 2014 Chatsiri Rattana.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/*  Titles			                                          Authors	         Date
 * Service supported by client_server                     R.Chatsiri
 */

#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include "internet/logger/logging.hpp"

namespace internet
{

		namespace asio = boost::asio;

    namespace service
    {

        class scan_dir_impl : public boost::enable_shared_from_this<scan_dir_impl>
        {

            public:


                scan_dir_impl() : scan_dir_work_(new asio::io_service::work(scan_dir_io_service_)),
                    scan_dir_thread_(boost::bind(&asio::io_service::run, &scan_dir_io_service_)) {


                }

                void read_msg_scan();

                void add_directory(const std::string dir_name);
	
								void destory();
				
            private:

                boost::asio::io_service  scan_dir_io_service_;
                boost::scoped_ptr<boost::asio::io_service::work>  scan_dir_work_;
                boost::thread  scan_dir_thread_;
        };


    }


}


#endif /* INTERNET_SERVICE_SCAN_DIR_IMPL_HPP */
