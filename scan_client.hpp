#ifndef INTERNET_SCAN_CLIENT_HPP
#define INTERNET_SCAN_CLIENT_HPP
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
 *- Scan client service call to server scan file          R.Chatsiri
 */

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/lexical_cast.hpp>

#include "internet/logger/logging.hpp"

#include "internet/msg/scan_server_client/message_scan.pb.h"

#include "internet/scan_client/packedmessage_scan_client.hpp"

#include "internet/scan_client/scan_dir.hpp"


namespace internet
{
    namespace asio = boost::asio;
    namespace service
    {

        struct file_detail {
            uint64_t uuid;
            enum scan_type { MD5, MD5_HEADER, MD5_BODY, SHA_1, SHA_256, SSDEEP };
            enum file_type { PE, ELF, PROCESS };
            std::string timestamp;
        };

        class scan_client // : public boost::enable_shared_from_this<scan_client>
        {

            public:

                typedef boost::shared_ptr<message_scan::RequestScan>  MsgsRequestPointer;
                typedef boost::shared_ptr<message_scan::ResponseScan> MsgsResponsePointer;

                scan_client(std::string ip_addr, std::string port) :
                    msgs_socket(io_service), // Initial socket.
										sdir(io_service),        // Scan dir
                    msgs_packed_request_scan(boost::shared_ptr<message_scan::RequestScan>
                            (new message_scan::RequestScan())),
                    msgs_packed_response_scan(boost::shared_ptr<message_scan::ResponseScan>
                            (new message_scan::ResponseScan())) {
                    try {

											
												int port_ = boost::lexical_cast<int>(port);
											  asio::ip::tcp::endpoint endpoint(asio::ip::address::from_string(ip_addr),port_);
												/*: Weak ptr  in shared_from_this() */
                        msgs_socket.async_connect(endpoint, boost::bind(&scan_client::on_connect,this,
                                asio::placeholders::error));
										
											  io_service.run(); 	

                    } catch(boost::system::system_error& error) {
											 LOG(INFO)<< " Error " << error.code();
                    }

                }

                MsgsRequestPointer prepare_start_request();

                void do_write_request(MsgsRequestPointer msgs_request);

                void on_connect(const boost::system::error_code& error);

                void start();

                //Pre-process file detail.
                void set_file_scan(std::string file_path);

            private:
                packedmessage_scan_client<message_scan::RequestScan>  msgs_packed_request_scan;

                packedmessage_scan_client<message_scan::ResponseScan> msgs_packed_response_scan;

                file_detail f_detail;

							  scan_dir sdir;

                asio::io_service io_service;
                asio::ip::tcp::socket msgs_socket;
        };

    }

}



#endif /* INTERNET_SCAN_CLIENT_HPP */
