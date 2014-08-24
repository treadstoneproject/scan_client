#ifndef INTERNET_SERVICE_BASIC_SCAN_DIR_HPP
#define INTERNET_SERVICE_BASIC_SCAN_DIR_HPP

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
 * 	
 */

#include <boost/asio.hpp>

#include "internet/scan_client/basic_scan_dir_service.hpp"

namespace internet
{

    namespace service
    {
        template<typename Service>
        class basic_scan_dir : public boost::asio::basic_io_object<Service>
        {

            public:
                explicit basic_scan_dir(boost::asio::io_service& io_service) :
                    boost::asio::basic_io_object<Service>(io_service) { }

                void add_directory(const std::string& dir_name);

            private:

        };


    }


}

#endif /* INTERNET_SERVICE_BASIC_SCAN_DIR_HPP */
